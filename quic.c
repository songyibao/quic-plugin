//
// Created by songyibao on 24-2-29.
//

#include "quic.h"
#include "client.h"
#include "mysqlite.h"
#include "neuron.h"
#include "quic_config.h"
#include "quic_handle.h"
#include "quic_utils.h"
#include <pthread.h>
#include <stdlib.h>

static const neu_plugin_intf_funs_t plugin_intf_funs = {
    .open = driver_open,
    .close = driver_close,
    .init = driver_init,
    .uninit = driver_uninit,
    .start = driver_start,
    .stop = driver_stop,
    .setting = driver_config,
    .request = driver_request,

    .driver.validate_tag = driver_validate_tag,
    .driver.group_timer = driver_group_timer,
    .driver.write_tag = driver_write,
};

const neu_plugin_module_t neu_plugin_module = {
    .schema = "quic",
    .version = NEURON_PLUGIN_VER_1_0,
    .module_name = "quic",
    .module_descr = "quic plugin",
    .module_descr_zh = "该插件用于连接使用 quic 协议的app,用户可选择作为客户端连接",
    .intf_funs = &plugin_intf_funs,
    .kind = NEU_PLUGIN_KIND_SYSTEM,
    .type = NEU_NA_TYPE_APP,
    .display = true,
    .single = false,
};

void *thread_client_start(void *arg)
{
    thread_args_t *local_args = arg;
    neu_plugin_t * plugin     = local_args->plugin;
    start_quic_client(plugin, (float) plugin->interval);
    return NULL;
}

int config_parse(neu_plugin_t *plugin, const char *setting)
{
    int   ret       = 0;
    char *err_param = NULL;

    neu_json_elem_t host            = { .name = "host", .t = NEU_JSON_STR };
    neu_json_elem_t port            = { .name = "port", .t = NEU_JSON_INT };
    neu_json_elem_t msg_buffer_size = { .name = "msg_buffer_size",
                                        .t = NEU_JSON_INT };
    neu_json_elem_t ips      = { .name = "ips", .t = NEU_JSON_STR };
    neu_json_elem_t interval = { .name = "interval", .t = NEU_JSON_INT };
    if (NULL == setting) {
        plog_error(plugin, "invalid argument, null pointer");
        return -1;
    }

    ret = neu_parse_param(setting, &err_param, 5, &host, &port,
                          &msg_buffer_size, &ips, &interval);
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

    if (msg_buffer_size.v.val_int < 0) {
        plog_error(plugin, "setting invalid msg_buffer_size: %" PRIi64,
                   msg_buffer_size.v.val_int);
        goto error;
    }
    // ips, required
    if (0 == strlen(ips.v.val_str)) {
        plog_error(plugin, "setting invalid host: `%s`", ips.v.val_str);
        goto error;
    }

    if (interval.v.val_int < 1 || interval.v.val_int > 65535) {
        plog_error(plugin, "setting invalid interval: %" PRIi64,
                   interval.v.val_int);
        goto error;
    }
    plugin->port = (char *) malloc(sizeof(char) * 10);
    plugin->host = host.v.val_str;
    snprintf(plugin->port, 10, "%lld", (long long) port.v.val_int);
    plugin->msg_buffer_size = msg_buffer_size.v.val_int;
    plugin->interval        = interval.v.val_int;

    if(plugin->keepalive_watcher.active){
        plog_debug(plugin,"重新设置keepalive_watcher定时器间隔");
        // 使用 ev_timer_set 重新设置定时器
        ev_timer_set(&plugin->keepalive_watcher, plugin->keepalive_watcher.at, plugin->interval);
        // 使用 ev_timer_again 重新启动定时器以应用新的设置
        ev_timer_again(plugin->loop, &plugin->keepalive_watcher);
    }


    char *token;
    // 复制ips.v.val_str
    char *tmp = (char *) malloc(sizeof(char) * (strlen(ips.v.val_str) + 1));
    strcpy(tmp, ips.v.val_str);
    // Extracting the first token
    token = strtok(tmp, ";");

    int i = 0;
    // Loop through the string to extract all other tokens
    while (token != NULL && i < MAX_IPS) {
        plugin->ips[i] = token;
        token          = strtok(NULL, ";");
        i++;
    }
    plugin->ip_count = i;
    for (int j = 0; j < i; j++) {
        plugin->thread_args[j].plugin          = plugin;
        plugin->thread_args[j].interface_index = j;
    }
    plog_notice(plugin, "config host            : %s", plugin->host);
    plog_notice(plugin, "config port            : %s", plugin->port);
    plog_notice(plugin, "config msg_buffer_size            : %hu",
                plugin->msg_buffer_size);
    plog_notice(plugin, "config interval            : %hu",
                plugin->interval);
    // Printing the extracted IPs
    printf("Extracted IPs:\n");
    plog_notice(plugin, "config %d ips:", plugin->ip_count);
    for (int j = 0; j < i; j++) {
        plog_notice(plugin, "%s", plugin->ips[j]);
    }
    return 0;

error:
    free(err_param);
    free(host.v.val_str);
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
    plog_notice(
        plugin,
        "============================================================\nconfig "
        "plugin============================================================\n");
    int rv = 0;

    if (0 != config_parse(plugin, setting)) {
        rv = NEU_ERR_NODE_SETTING_INVALID;
        goto error;
    }

    return rv;

error:
    plog_error(plugin, "config failure");
    return rv;
}

static int driver_start(neu_plugin_t *plugin)
{

    plog_notice(
        plugin,
        "============================================================\nstart "
        "plugin============================================================\n");
    // init sqlite3
    plugin->table_name = "json_data";
    init_database(&(plugin->db), "persistence/quic.db");
    if (!table_exists(plugin->db, plugin->table_name)) {
        create_table(plugin->db, plugin->table_name);
    }

    // timer init to 0
    plugin->timer = 0;
    // start plugin
    plugin->started = true;

    plugin->thread_client_start_args.plugin = plugin;
    if (pthread_create(&plugin->thread_client_start_id, NULL,
                       thread_client_start,
                       &plugin->thread_client_start_args) != 0) {
        printf("Error creating start thread.\n");
    }
    // start_quic_client(plugin);
    return 0;
}

static int driver_stop(neu_plugin_t *plugin)
{
    plog_notice(
        plugin,
        "============================================================\nstop "
        "plugin============================================================\n");

    plog_debug(plugin,"等待线程结束");
    // stop plugin, set plugin->started to false
    plugin->started = false;
    plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    pthread_join(plugin->thread_client_start_id, NULL);
    close_database(plugin->db);
    return 0;
}

static int driver_uninit(neu_plugin_t *plugin)
{
    plog_notice(
        plugin,
        "============================================================\nuninit "
        "plugin============================================================\n");

    free(plugin->host);
    free(plugin->port);
    for (int i = 0; i < plugin->ip_count; i++) {
        free(plugin->ips[i]);
    }
    free(plugin->table_name);

    free(plugin);
    nlog_debug("uninit success");
    return NEU_ERR_SUCCESS;
}

static int driver_request(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                          void *        data)
{
    plog_notice(
        plugin,
        "============================================================request "
        "plugin============================================================\n");
    neu_err_code_e error = NEU_ERR_SUCCESS;

    if (plugin->started == false) {
        error = NEU_ERR_NODE_IS_STOPED;
        goto exit;
    }

    switch (head->type) {

    case NEU_REQRESP_TRANS_DATA: {
        //        if(plugin->common.link_state == false) {
        //            error = NEU_ERR_NODE_NOT_READY;
        //            goto exit;
        //        }
        if (plugin->started == false) {
            error = NEU_ERR_NODE_NOT_READY;
            goto exit;
        }
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_TRANS_DATA_5S, 1, NULL);
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_TRANS_DATA_30S, 1, NULL);
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_TRANS_DATA_60S, 1, NULL);
        error = handle_insert_data(plugin, data);
        //        error = handle_trans_data(plugin, data);
        break;
    }
    default:
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
                        neu_value_u   value)
{
    (void) plugin;
    (void) req;
    (void) tag;
    (void) value;

    return 0;
}