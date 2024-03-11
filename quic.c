//
// Created by songyibao on 24-2-29.
//

#include <stdlib.h>
#include <pthread.h>
#include "client.h"
#include "neuron.h"
#include "quic.h"
#include "quic_config.h"
#include "quic_handle.h"

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
neu_plugin_t *local_plugin;
int                  free_client(simple_client_t client)
{
    if (client.peer != NULL) {
        freeaddrinfo(client.peer);
    }
    if (client.ssl_ctx != NULL) {
        SSL_CTX_free(client.ssl_ctx);
    }
    if (client.sock > 0) {
        close(client.sock);
    }
    if (client.quic_endpoint != NULL) {
        quic_endpoint_close(client.quic_endpoint, true);
        quic_endpoint_free(client.quic_endpoint);
    }
    if (client.loop != NULL) {
        ev_loop_destroy(client.loop);
    }
    if (client.config != NULL) {
        quic_config_free(client.config);
    }
    return 0;
}
int config_parse(neu_plugin_t *plugin, const char *setting, char *chost,
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
    local_plugin = plugin;
    (void) load;
    plog_notice(
        plugin,
        "============================================================"
        "\ninitialize "
        "plugin============================================================\n");
    NEU_PLUGIN_REGISTER_METRIC(plugin, NEU_METRIC_TRANS_DATA_5S, 5000);
    NEU_PLUGIN_REGISTER_METRIC(plugin, NEU_METRIC_TRANS_DATA_30S, 30000);
    NEU_PLUGIN_REGISTER_METRIC(plugin, NEU_METRIC_TRANS_DATA_60S, 60000);
    return 0;
}
static int driver_config(neu_plugin_t *plugin, const char *setting)
{
    local_plugin = plugin;
    plog_notice(
        plugin,
        "============================================================\nconfig "
        "plugin============================================================\n");
    int rv = 0;

    if (0 != config_parse(plugin, setting, plugin->host, plugin->port)) {
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

static int driver_start(neu_plugin_t *plugin)
{
//    if (plugin->common.link_state == NEU_NODE_LINK_STATE_DISCONNECTED){
//        return NEU_ERR_NODE_NOT_READY;
//    }
    plog_notice(
        plugin,
        "============================================================\nstart "
        "plugin============================================================\n");
    local_plugin = plugin;
    //timer init to 0
    plugin->timer = 0;
    // start plugin
    plugin->started = true;
    return 0;
}

static int driver_stop(neu_plugin_t *plugin)
{
    local_plugin = NULL;
    plog_notice(
        plugin,
        "============================================================\nstop "
        "plugin============================================================\n");
    // stop plugin
    plugin->started = false;
    // plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;

    return 0;
}

static int driver_uninit(neu_plugin_t *plugin)
{
    local_plugin = NULL;
    plog_notice(
        plugin,
        "============================================================\nuninit "
        "plugin============================================================\n");
    free_client(plugin->client);
    // free(&plugin->client);
    free(plugin->host);
    free(plugin->port);
    free(plugin);

    plog_notice(plugin, "uninitialize plugin `%s` success",
                neu_plugin_module.module_name);
    return NEU_ERR_SUCCESS;
}

static int driver_request(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                          void *data)
{
    local_plugin = plugin;

    // check link status once every 3 seconds
    plugin->timer++;
    if(plugin->timer == 3){
        plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
        new_client(plugin,example_timeout_callback,client_on_conn_established);
        plugin->timer = 0;
    }


    neu_err_code_e error = NEU_ERR_SUCCESS;
    if(plugin->started == false || plugin->common.link_state == NEU_NODE_LINK_STATE_DISCONNECTED) {
        error = NEU_ERR_NODE_IS_STOPED;
        goto exit;
    }
    plog_notice(
        plugin,
        "============================================================\nrequest "
        "plugin============================================================\n");
    plog_notice(plugin, "Start request function");


    // update cached messages number per seconds
    //    if (NULL != plugin->client &&
    //        (global_timestamp - plugin->cache_metric_update_ts) >= 1000) {
    //        NEU_PLUGIN_UPDATE_METRIC(
    //            plugin, NEU_METRIC_CACHED_MSGS_NUM,
    //            neu_mqtt_client_get_cached_msgs_num(plugin->client), NULL);
    //        plugin->cache_metric_update_ts = global_timestamp;
    //    }
    switch (head->type) {
    // case NEU_RESP_ERROR:
    //     //        error = handle_write_response(plugin, head->ctx, data);
    //     break;
    // case NEU_RESP_READ_GROUP:
    //     error = handle_read_response(plugin, head->ctx, data);
    //     break;
    case NEU_REQRESP_TRANS_DATA: {
        if(plugin->common.link_state == false) {
            error = NEU_ERR_NODE_NOT_READY;
            goto exit;
        }
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_TRANS_DATA_5S, 1, NULL);
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_TRANS_DATA_30S, 1, NULL);
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_TRANS_DATA_60S, 1, NULL);
        error = handle_trans_data(plugin, data);
        break;
    }
    // case NEU_REQ_SUBSCRIBE_GROUP:
    //     error = handle_subscribe_group(plugin, data);
    //     break;
    // case NEU_REQ_UPDATE_SUBSCRIBE_GROUP:
    //     error = handle_update_subscribe(plugin, data);
    //     break;
    // case NEU_REQ_UNSUBSCRIBE_GROUP:
    //     error = handle_unsubscribe_group(plugin, data);
    //     break;
    // case NEU_REQ_UPDATE_GROUP:
    //     error = handle_update_group(plugin, data);
    //     break;
    // case NEU_REQ_UPDATE_NODE:
    //     error = handle_update_driver(plugin, data);
    //     break;
    // case NEU_REQRESP_NODE_DELETED:
    //     error = handle_del_driver(plugin, data);
    //     break;
    default:
        // error = NEU_ERR_MQTT_FAILURE;
        break;
    }
    plog_notice(plugin, "Exit request function");
    return error;

exit:
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