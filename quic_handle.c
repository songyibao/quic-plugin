#include <utils/asprintf.h>

#include "json_rw.h"
#include "quic.h"
#include "quic_handle.h"
static neu_reqresp_trans_data_t *local_trans_data;
static neu_plugin_t             *local_plugin;

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
int free_client(simple_client_t client)
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
void on_conn_established(void *tctx, struct quic_conn_t *conn)
{
    // Call function to send JSON data
    // parse_send_data(local_plugin, conn, local_trans_data);
    free_client(local_plugin->client);
}
void on_stream_writable(void *tctx, struct quic_conn_t *conn,
                        uint64_t stream_id)
{
    quic_stream_wantwrite(conn, stream_id, false);
}
const struct quic_transport_methods_t quic_transport_methods = {
    .on_conn_created     = client_on_conn_created,
    .on_conn_established = on_conn_established,
    .on_conn_closed      = client_on_conn_closed,
    .on_stream_created   = client_on_stream_created,
    .on_stream_readable  = client_on_stream_readable,
    .on_stream_writable  = on_stream_writable,
    .on_stream_closed    = client_on_stream_closed,
};

const struct quic_packet_send_methods_t quic_packet_send_methods = {
    .on_packets_send = client_on_packets_send,
};

int handle_read_response(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt_json,
                         neu_resp_read_group_t *data)
{
}
int set_quic_client_config(neu_plugin_t *plugin)
{
    plog_notice(plugin, "Create quic config");
    // Create quic config.
    quic_config_t *new_config = quic_config_new();
    (plugin->client).config   = quic_config_new();
    if (new_config == NULL) {
        // fprintf(stderr, "failed to create config\n");
        // ret = -1;
        // goto EXIT;
        plog_notice(plugin, "failed to create new config");
    }
    quic_config_set_max_idle_timeout(new_config, 5000);
    quic_config_set_recv_udp_payload_size(new_config, MAX_DATAGRAM_SIZE);

    plog_notice(plugin, "Create and set tls config");
    // Create and set tls config.
    if (client_load_ssl_ctx(&plugin->client) != 0) {
        // ret = -1;
        // goto EXIT;
        plog_notice(plugin, "failed to create tls config");
    }
    quic_config_set_tls_config(new_config, plugin->client.ssl_ctx);
    // save config
    (plugin->client).config = new_config;
    return 0;
}
int create_quic_endpoint(neu_plugin_t *plugin)
{
    plog_notice(plugin, "Create quic endpoint");
    // Create quic endpoint
    plugin->client.quic_endpoint = quic_endpoint_new(
        (plugin->client).config, false, &quic_transport_methods,
        &(plugin->client), &quic_packet_send_methods, &(plugin->client));
    if (plugin->client.quic_endpoint == NULL) {
        // fprintf(stderr, "failed to create quic endpoint\n");
        // ret = -1;
        plog_notice(plugin, "failed to create quic endpoint");
        // goto error;
    }
    plog_notice(plugin, "Init event loop.");
    // Init event loop.
    plugin->client.loop = ev_default_loop(0);
    ev_init(&(plugin->client.timer), timeout_callback);
    plugin->client.timer.data = &(plugin->client);
    plog_notice(plugin, "Exit create_quic_endpoint function");
    return 0;
}

int handle_trans_data(neu_plugin_t             *plugin,
                      neu_reqresp_trans_data_t *trans_data)
{
    local_trans_data = trans_data;
    local_plugin     = plugin;

    set_quic_client_config(plugin);
    create_quic_endpoint(plugin);
    int ret = 0;
    // Connect to server.
    uint64_t conn_index;
    ret = quic_endpoint_connect(
        plugin->client.quic_endpoint,
        (struct sockaddr *) &(plugin->client.local_addr),
        plugin->client.local_addr_len, (plugin->client).peer->ai_addr,
        (plugin->client).peer->ai_addrlen, NULL, NULL, 0, NULL, 0, &conn_index);
    if (ret < 0) {
        ret = -1;
        // goto EXIT;
        plog_notice(plugin, "failed to connect to server: %d\n", ret);
    }
    process_connections(&(plugin->client));

    // Start event loop.
    ev_io watcher;
    ev_io_init(&watcher, read_callback, plugin->client.sock, EV_READ);
    ev_io_start(plugin->client.loop, &watcher);
    watcher.data = &(plugin->client);
    ev_loop(plugin->client.loop, 0);

    // while(!quic_stream_finished((plugin->client).conn,0)){}
    free_client(plugin->client);
    plog_notice(plugin, "Exit handle_trans_data function");
    return ret;
}

static inline char *default_upload_topic(neu_req_subscribe_t *info)
{
    char *t = NULL;
    neu_asprintf(&t, "/neuron/%s/%s/%s", info->app, info->driver, info->group);
    return t;
}

int handle_subscribe_group(neu_plugin_t *plugin, neu_req_subscribe_t *sub_info)
{
    //     int rv = 0;
    //
    //     neu_json_elem_t topic = { .name = "topic", .t = NEU_JSON_STR };
    //     if (NULL == sub_info->params) {
    //         // no parameters, try default topic
    //         topic.v.val_str = default_upload_topic(sub_info);
    //         if (NULL == topic.v.val_str) {
    //             rv = NEU_ERR_EINTERNAL;
    //             goto end;
    //         }
    //     } else if (0 != neu_parse_param(sub_info->params, NULL, 1, &topic)) {
    //         plog_error(plugin, "parse `%s` for topic fail",
    //         sub_info->params); rv = NEU_ERR_GROUP_PARAMETER_INVALID; goto
    //         end;
    //     }
    //
    //     rv = route_tbl_add_new(&plugin->route_tbl, sub_info->driver,
    //                            sub_info->group, topic.v.val_str);
    //     // topic.v.val_str ownership moved
    //     if (0 != rv) {
    //         plog_error(plugin, "route driver:%s group:%s fail, `%s`",
    //                    sub_info->driver, sub_info->group, sub_info->params);
    //         goto end;
    //     }
    //
    //     plog_notice(plugin, "route driver:%s group:%s to topic:%s",
    //                 sub_info->driver, sub_info->group, topic.v.val_str);
    //
    // end:
    //     free(sub_info->params);
    //     return rv;
}

int handle_update_subscribe(neu_plugin_t *plugin, neu_req_subscribe_t *sub_info)
{
    int rv = 0;

    if (NULL == sub_info->params) {
        rv = NEU_ERR_GROUP_PARAMETER_INVALID;
        goto end;
    }

    neu_json_elem_t topic = { .name = "topic", .t = NEU_JSON_STR };
    if (0 != neu_parse_param(sub_info->params, NULL, 1, &topic)) {
        plog_error(plugin, "parse `%s` for topic fail", sub_info->params);
        rv = NEU_ERR_GROUP_PARAMETER_INVALID;
        goto end;
    }

    // rv = route_tbl_update(&plugin->route_tbl, sub_info->driver,
    // sub_info->group,
    //                       topic.v.val_str);
    // topic.v.val_str ownership moved
    if (0 != rv) {
        plog_error(plugin, "route driver:%s group:%s fail, `%s`",
                   sub_info->driver, sub_info->group, sub_info->params);
        goto end;
    }

    plog_notice(plugin, "route driver:%s group:%s to topic:%s",
                sub_info->driver, sub_info->group, topic.v.val_str);

end:
    free(sub_info->params);
    return rv;
}

int handle_unsubscribe_group(neu_plugin_t          *plugin,
                             neu_req_unsubscribe_t *unsub_info)
{
    // route_tbl_del(&plugin->route_tbl, unsub_info->driver, unsub_info->group);
    // plog_notice(plugin, "del route driver:%s group:%s", unsub_info->driver,
    //             unsub_info->group);
    // return 0;
}

int handle_update_group(neu_plugin_t *plugin, neu_req_update_group_t *req)
{
    // route_tbl_update_group(&plugin->route_tbl, req->driver, req->group,
    //                        req->new_name);
    // plog_notice(plugin, "update route driver:%s group:%s to %s", req->driver,
    //             req->group, req->new_name);
    // return 0;
}

int handle_update_driver(neu_plugin_t *plugin, neu_req_update_node_t *req)
{
    // route_tbl_update_driver(&plugin->route_tbl, req->node, req->new_name);
    // plog_notice(plugin, "update route driver:%s to %s", req->node,
    //             req->new_name);
    // return 0;
}

int handle_del_driver(neu_plugin_t *plugin, neu_reqresp_node_deleted_t *req)
{
    // route_tbl_del_driver(&plugin->route_tbl, req->node);
    // plog_notice(plugin, "delete route driver:%s", req->node);
    // return 0;
}
