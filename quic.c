//
// Created by songyibao on 24-2-29.
//
#include <stdlib.h>

#include "client.h"
#include <neuron.h>

static neu_plugin_t *driver_open(void);

static int driver_close(neu_plugin_t *plugin);
static int driver_init(neu_plugin_t *plugin, bool load);
static int driver_uninit(neu_plugin_t *plugin);
static int driver_start(neu_plugin_t *plugin);
static int driver_stop(neu_plugin_t *plugin);
static int driver_config(neu_plugin_t *plugin, const char *config);
static int driver_request(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                          void *data);

static int driver_validate_tag(neu_plugin_t *plugin, neu_datatag_t *tag);
static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group);
static int driver_write(neu_plugin_t *plugin, void *req, neu_datatag_t *tag,
                        neu_value_u value);

static const neu_plugin_intf_funs_t plugin_intf_funs = {
    .open    = driver_open,
    .close   = driver_close,
    .init    = driver_init,
    .uninit  = driver_uninit,
    .start   = driver_start,
    .stop    = driver_stop,
    .setting = driver_config,
    .request = driver_request,

    .driver.validate_tag = driver_validate_tag,
    .driver.group_timer  = driver_group_timer,
    .driver.write_tag    = driver_write,
};

const neu_plugin_module_t neu_plugin_module = {
    .schema          = "quic",
    .version         = NEURON_PLUGIN_VER_1_0,
    .module_name     = "quic",
    .module_descr    = "quic plugin",
    .module_descr_zh = "该插件用于连接使用 quic 协议的app。"
                       "用户可选择作为客户端连接",
    .intf_funs       = &plugin_intf_funs,
    .kind            = NEU_PLUGIN_KIND_SYSTEM,
    .type            = NEU_NA_TYPE_APP,
    .display         = true,
    .single          = false,
};

struct neu_plugin {
    neu_plugin_common_t  common;
    struct simple_client client;
    quic_config_t       *config;
    struct addrinfo     *peer;
};

static neu_plugin_t *driver_open(void)
{
    neu_plugin_t *plugin = calloc(1, sizeof(neu_plugin_t));

    neu_plugin_common_init(&plugin->common);

    return plugin;
}

static int driver_close(neu_plugin_t *plugin)
{
    free(plugin);

    return 0;
}

static int driver_init(neu_plugin_t *plugin, bool load)
{
    (void) load;
    // Set logger.
    quic_set_logger(debug_log, NULL, QUIC_LOG_LEVEL_TRACE);

    // Create client.
    struct simple_client client;
    client.quic_endpoint = NULL;
    client.ssl_ctx       = NULL;
    client.conn          = NULL;
    client.loop          = NULL;
    int ret              = 0;

    // Create socket.
    const char *host = "127.0.0.1";
    const char *port = "4433";
    // struct addrinfo *peer = NULL;
    if (create_socket(host, port, &(plugin->peer), &client) != 0) {
        ret = -1;
        // goto EXIT;
        plog_notice(plugin, "node: socket created failed");
    }

    // Create quic config.
    plugin->config = quic_config_new();
    if (plugin->config == NULL) {
        // fprintf(stderr, "failed to create config\n");
        ret = -1;
        // goto EXIT;
        plog_notice(plugin, "failed to create config");
    }
    quic_config_set_max_idle_timeout(plugin->config, 5000);
    quic_config_set_recv_udp_payload_size(plugin->config, MAX_DATAGRAM_SIZE);

    // Create and set tls config.
    if (client_load_ssl_ctx(&client) != 0) {
        ret = -1;
        // goto EXIT;
        plog_notice(plugin, "failed to create tls config");
    }
    quic_config_set_tls_config(plugin->config, client.ssl_ctx);

    plugin->client = client;
    plog_notice(plugin, "node: quic init");

    return 0;
}

static int driver_uninit(neu_plugin_t *plugin)
{
    // if (peer != NULL) {
    //     freeaddrinfo(peer);
    // }
    if (plugin->client.ssl_ctx != NULL) {
        SSL_CTX_free(plugin->client.ssl_ctx);
    }
    if (plugin->client.sock > 0) {
        close(plugin->client.sock);
    }
    if (plugin->client.quic_endpoint != NULL) {
        quic_endpoint_free(plugin->client.quic_endpoint);
    }
    if (plugin->client.loop != NULL) {
        ev_loop_destroy(plugin->client.loop);
    }
    if (plugin->config != NULL) {
        quic_config_free(plugin->config);
    }

    plog_notice(plugin, "node: lsquic uninit");

    return 0;
}

static int driver_start(neu_plugin_t *plugin)
{
    // Create quic endpoint
    plugin->client.quic_endpoint = quic_endpoint_new(
        plugin->config, false, &quic_transport_methods, &(plugin->client),
        &quic_packet_send_methods, &(plugin->client));
    if (plugin->client.quic_endpoint == NULL) {
        // fprintf(stderr, "failed to create quic endpoint\n");
        // ret = -1;
        // goto EXIT;
        plog_notice(plugin, "failed to create quic endpoint");
    }

    // Init event loop.
    plugin->client.loop = ev_default_loop(0);
    ev_init(&(plugin->client.timer), timeout_callback);
    plugin->client.timer.data = &(plugin->client);

    int ret;
    // Connect to server.
    ret = quic_endpoint_connect(
        plugin->client.quic_endpoint,
        (struct sockaddr *) &(plugin->client.local_addr),
        plugin->client.local_addr_len, plugin->peer->ai_addr,
        plugin->peer->ai_addrlen, NULL /* client_name*/, NULL /* session */,
        0 /* session_len */, NULL /* token */, 0 /* token_len */,
        NULL /*index*/);
    if (ret < 0) {
        fprintf(stderr, "failed to connect to client: %d\n", ret);
        ret = -1;
        // goto EXIT;
        plog_notice(plugin, "failed to connect to client: ");
    }
    process_connections(&(plugin->client));

    // Start event loop.
    ev_io watcher;
    ev_io_init(&watcher, read_callback, plugin->client.sock, EV_READ);
    ev_io_start(plugin->client.loop, &watcher);
    watcher.data = &(plugin->client);
    ev_loop(plugin->client.loop, 0);
    plog_notice(plugin, "node: quic start");

    return 0;
}

static int driver_stop(neu_plugin_t *plugin)
{
    plog_notice(plugin, "node: lsquic stop");
    return 0;
}

static int driver_config(neu_plugin_t *plugin, const char *config)
{
    plog_notice(plugin, "config: %s", config);

    return 0;
}

static int driver_request(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                          void *data)
{
    (void) data;
    (void) plugin;
    (void) head;

    return 0;
}

static int driver_validate_tag(neu_plugin_t *plugin, neu_datatag_t *tag)
{
    plog_notice(plugin, "validate tag: %s", tag->name);

    return 0;
}

static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group)
{
    (void) plugin;
    (void) group;

    plog_notice(plugin, "timer....");

    return 0;
}

static int driver_write(neu_plugin_t *plugin, void *req, neu_datatag_t *tag,
                        neu_value_u value)
{
    (void) plugin;
    (void) req;
    (void) tag;
    (void) value;

    return 0;
}