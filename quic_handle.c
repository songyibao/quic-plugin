#include <utils/asprintf.h>

#include "client.h"
#include "json_rw.h"
#include "neuron.h"
#include "plugin.h"
#include "quic.h"
#include "quic_handle.h"
static neu_reqresp_trans_data_t *local_trans_data;
static ev_io                     watcher;
int parse_send_data(neu_plugin_t *plugin, quic_conn_t *conn,
                    neu_reqresp_trans_data_t *trans_data)
{
    plog_notice(plugin, "start parse json ");
    int              ret      = 0;
    char            *json_str = NULL;
    json_read_resp_t resp     = {
            .plugin     = plugin,
            .trans_data = trans_data,
    };
    int rv = neu_json_encode_by_fn(&resp, json_encode_read_resp, &json_str);
    if (rv != 0) {
        plog_notice(plugin, "parse json failed");
    } else {
        plog_notice(plugin, "parse json str succeed: %s", json_str);
    }
    // Sending JSON data to the server
    quic_stream_write(conn, 0, (uint8_t *) json_str, strlen(json_str), true);
    return ret;
}
void on_conn_established(void *tctx, struct quic_conn_t *conn)
{
    quic_stream_wantwrite(conn, 0, true);
    // Call function to send JSON data
    parse_send_data(local_plugin, conn, local_trans_data);
}

int handle_read_response(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt_json,
                         neu_resp_read_group_t *data)
{
    int res = 0;
    return res;
}

int handle_trans_data(neu_plugin_t             *plugin,
                      neu_reqresp_trans_data_t *trans_data)
{
    int ret          = 0;
    local_trans_data = trans_data;
    local_plugin     = plugin;

    new_client(plugin,example_timeout_callback,on_conn_established);
    plog_notice(plugin, "Exit handle_trans_data function");

    // free_client(plugin->client);
    local_plugin     = NULL;
    local_trans_data = NULL;

    return ret;
error:
    return ret;
}

static inline char *default_upload_topic(neu_req_subscribe_t *info)
{
    char *t = NULL;
    neu_asprintf(&t, "/neuron/%s/%s/%s", info->app, info->driver, info->group);
    return t;
}
