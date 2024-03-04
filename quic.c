//
// Created by songyibao on 24-2-29.
//

#include <stdlib.h>
//#include "client.h"
#include "neuron.h"
#include "quic_config.h"
#include "quic.h"
#include "quic_handle.h"
struct neu_plugin {
    neu_plugin_common_t  common;
    struct simple_client client;
    quic_config_t       *config;
    struct addrinfo     *peer;
    char                *host;
    char                *port;
};


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
    // Create socket.
    // const char *host = "127.0.0.1";
    // const char *port = "4433";
    // struct addrinfo *peer = NULL;
    // int ret              = 0;
    plog_notice(plugin, "bofore create socket, host:%s, port:%s", plugin->host,
                plugin->port);
    if (create_socket(plugin->host, plugin->port, &(plugin->peer),
                      &plugin->client) != 0) {
        // ret = -1;
        // goto EXIT;
        plog_notice(plugin, "node: socket created failed");
    }

    // Create quic config.
    plugin->config = quic_config_new();
    if (plugin->config == NULL) {
        // fprintf(stderr, "failed to create config\n");
        // ret = -1;
        // goto EXIT;
        plog_notice(plugin, "failed to create config");
    }
    quic_config_set_max_idle_timeout(plugin->config, 5000);
    quic_config_set_recv_udp_payload_size(plugin->config, MAX_DATAGRAM_SIZE);

    // Create and set tls config.
    if (client_load_ssl_ctx(&plugin->client) != 0) {
        // ret = -1;
        // goto EXIT;
        plog_notice(plugin, "failed to create tls config");
    }
    quic_config_set_tls_config(plugin->config, plugin->client.ssl_ctx);
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

//    int ret;
//    // Connect to server.
//    ret = quic_endpoint_connect(
//        plugin->client.quic_endpoint,
//        (struct sockaddr *) &(plugin->client.local_addr),
//        plugin->client.local_addr_len, plugin->peer->ai_addr,
//        plugin->peer->ai_addrlen, NULL /* client_name*/, NULL /* session */,
//        0 /* session_len */, NULL /* token */, 0 /* token_len */,
//        NULL /*index*/);
//    if (ret < 0) {
//        fprintf(stderr, "failed to connect to client: %d\n", ret);
//        ret = -1;
//        // goto EXIT;
//        plog_notice(plugin, "failed to connect to client: ");
//    }
//    process_connections(&(plugin->client));
//
//    // Start event loop.
//    ev_io watcher;
//    ev_io_init(&watcher, read_callback, plugin->client.sock, EV_READ);
//    ev_io_start(plugin->client.loop, &watcher);
//    watcher.data = &(plugin->client);
//    ev_loop(plugin->client.loop, 0);
//    plog_notice(plugin, "node: quic start");

    return 0;
}

static int driver_stop(neu_plugin_t *plugin)
{
    plog_notice(plugin, "node: lsquic stop");
    return 0;
}

static int parse_config(neu_plugin_t *plugin, const char *setting,
                        char **host_p, uint16_t *port_p)
{
    char           *err_param = NULL;
    neu_json_elem_t host      = { .name = "host", .t = NEU_JSON_STR };
    neu_json_elem_t port      = { .name = "port", .t = NEU_JSON_INT };

    if (0 != neu_parse_param(setting, &err_param, 2, &host, &port)) {
        plog_error(plugin, "parsing setting fail, key: `%s`", err_param);
        goto error;
    }

    // host, required
    if (0 == strlen(host.v.val_str)) {
        plog_error(plugin, "setting invalid host: `%s`", host.v.val_str);
        goto error;
    }

    // port, required
    if (0 == port.v.val_int || port.v.val_int > 65535) {
        plog_error(plugin, "setting invalid port: %" PRIi64, port.v.val_int);
        goto error;
    }

    *host_p = host.v.val_str;
    *port_p = port.v.val_int;

    plog_notice(plugin, "config host:%s port:%" PRIu16, *host_p, *port_p);

    return 0;

error:
    free(err_param);
    free(host.v.val_str);
    return -1;
}
int mqtt_config_parse(neu_plugin_t *plugin, const char *setting, char *chost,
                      char *cport)
{
    int   ret       = 0;
    char *err_param = NULL;

    neu_json_elem_t host = { .name = "host", .t = NEU_JSON_STR };
    neu_json_elem_t port = { .name = "port", .t = NEU_JSON_INT };

    if (NULL == setting) {
        plog_error(plugin, "test");
        plog_error(plugin, "invalid argument, null pointer");
        return -1;
    }

    ret = neu_parse_param(setting, &err_param, 2, &host, &port);
    if (0 != ret) {
        plog_error(plugin, "parsing setting fail, key: `%s`", err_param);
        goto error;
    }

    // host, required
    if (0 == strlen(host.v.val_str)) {
        plog_error(plugin, "setting invalid host: `%s`", host.v.val_str);
        goto error;
    }

    // port, required
    if (0 == port.v.val_int || port.v.val_int > 65535) {
        plog_error(plugin, "setting invalid port: %" PRIi64, port.v.val_int);
        goto error;
    }
    cport = (char *) malloc(sizeof(char) * 10);
    chost = host.v.val_str;
    snprintf(cport, 10, "%lld", (long long) port.v.val_int);

    plog_notice(plugin, "config host            : %s", chost);
    plog_notice(plugin, "config port            : %s", cport);
    plugin->host = chost;
    plugin->port = cport;
    return 0;

error:
    free(err_param);
    free(host.v.val_str);
    // ?
    // free(port.v.val_int);
    return -1;
}
static int driver_config(neu_plugin_t *plugin, const char *setting)
{
    int rv = 0;

    if (0 != mqtt_config_parse(plugin, setting, plugin->host, plugin->port)) {
        rv = NEU_ERR_NODE_SETTING_INVALID;
        goto error;
    }

    // stop the plugin if started
    // if (plugin->started) {
    //     stop(plugin);
    // }

    // check we could start the plugin with the new setting

    plog_notice(plugin, "config host:%s port:%s", plugin->host, plugin->port);

    return rv;

error:
    plog_error(plugin, "config failure");
    return rv;
}

static int driver_request(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                          void *data)
{
    neu_err_code_e error = NEU_ERR_SUCCESS;

    // update cached messages number per seconds
//    if (NULL != plugin->client &&
//        (global_timestamp - plugin->cache_metric_update_ts) >= 1000) {
//        NEU_PLUGIN_UPDATE_METRIC(
//            plugin, NEU_METRIC_CACHED_MSGS_NUM,
//            neu_mqtt_client_get_cached_msgs_num(plugin->client), NULL);
//        plugin->cache_metric_update_ts = global_timestamp;
//    }

    switch (head->type) {
    case NEU_RESP_ERROR:
//        error = handle_write_response(plugin, head->ctx, data);
        break;
    case NEU_RESP_READ_GROUP:
        error = handle_read_response(plugin, head->ctx, data);
        break;
    case NEU_REQRESP_TRANS_DATA: {
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_TRANS_DATA_5S, 1, NULL);
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_TRANS_DATA_30S, 1, NULL);
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_TRANS_DATA_60S, 1, NULL);
        error = handle_trans_data(plugin, data);
        break;
    }
    case NEU_REQ_SUBSCRIBE_GROUP:
        error = handle_subscribe_group(plugin, data);
        break;
    case NEU_REQ_UPDATE_SUBSCRIBE_GROUP:
        error = handle_update_subscribe(plugin, data);
        break;
    case NEU_REQ_UNSUBSCRIBE_GROUP:
        error = handle_unsubscribe_group(plugin, data);
        break;
    case NEU_REQ_UPDATE_GROUP:
        error = handle_update_group(plugin, data);
        break;
    case NEU_REQ_UPDATE_NODE:
        error = handle_update_driver(plugin, data);
        break;
    case NEU_REQRESP_NODE_DELETED:
        error = handle_del_driver(plugin, data);
        break;
    default:
        error = NEU_ERR_MQTT_FAILURE;
        break;
    }

    return error;
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