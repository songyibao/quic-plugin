#include "quic_handle.h"
#include "plugin.h"
static int tag_values_to_json(UT_array *tags, neu_json_read_resp_t *json)
{
    int index = 0;

    if (0 == utarray_len(tags)) {
        return 0;
    }

    json->n_tag = utarray_len(tags);
    json->tags  = (neu_json_read_resp_tag_t *) calloc(
        json->n_tag, sizeof(neu_json_read_resp_tag_t));
    if (NULL == json->tags) {
        return -1;
    }

    utarray_foreach(tags, neu_resp_tag_value_meta_t *, tag_value)
    {
        neu_tag_value_to_json(tag_value, &json->tags[index]);
        index += 1;
    }

    return 0;
}

// static char *generate_upload_json(neu_plugin_t *            plugin,
//                                  neu_reqresp_trans_data_t *data,
//                                  mqtt_upload_format_e      format)
//{
//    char *                   json_str = NULL;
//    neu_json_read_periodic_t header   = { .group     = (char *) data->group,
//                                          .node      = (char *) data->driver,
//                                          .timestamp = global_timestamp };
//    neu_json_read_resp_t     json     = { 0 };
//
//    if (0 != tag_values_to_json(data->tags, &json)) {
//        plog_error(plugin, "tag_values_to_json fail");
//        return NULL;
//    }
//
//    if (MQTT_UPLOAD_FORMAT_VALUES == format) { // values
//        neu_json_encode_with_mqtt(&json, neu_json_encode_read_resp1, &header,
//                                  neu_json_encode_read_periodic_resp,
//                                  &json_str);
//    } else if (MQTT_UPLOAD_FORMAT_TAGS == format) { // tags
//        neu_json_encode_with_mqtt(&json, neu_json_encode_read_resp, &header,
//                                  neu_json_encode_read_periodic_resp,
//                                  &json_str);
//    } else {
//        plog_warn(plugin, "invalid upload format: %d", format);
//    }
//
//    for (int i = 0; i < json.n_tag; i++) {
//        if (json.tags[i].n_meta > 0) {
//            free(json.tags[i].metas);
//        }
//    }
//
//    if (json.tags) {
//        free(json.tags);
//    }
//    return json_str;
// }

static char *generate_read_resp_json(neu_plugin_t          *plugin,
                                     neu_json_mqtt_t       *mqtt,
                                     neu_resp_read_group_t *data)
{
    // neu_resp_tag_value_meta_t *tags     = data->tags;
    // uint16_t                   len      = data->n_tag;
    char                *json_str = NULL;
    neu_json_read_resp_t json     = { 0 };

    if (0 != tag_values_to_json(data->tags, &json)) {
        plog_error(plugin, "tag_values_to_json fail");
        return NULL;
    }

    neu_json_encode_with_mqtt(&json, neu_json_encode_read_resp, mqtt,
                              neu_json_encode_mqtt_resp, &json_str);

    if (json.tags) {
        free(json.tags);
    }
    return json_str;
}

static char *generate_write_resp_json(neu_plugin_t     *plugin,
                                      neu_json_mqtt_t  *mqtt,
                                      neu_resp_error_t *data)
{
    (void) plugin;

    neu_json_error_resp_t error    = { .error = data->error };
    char                 *json_str = NULL;

    neu_json_encode_with_mqtt(&error, neu_json_encode_error_resp, mqtt,
                              neu_json_encode_mqtt_resp, &json_str);

    return json_str;
}

static inline int send_read_req(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt,
                                neu_json_read_req_t *req)
{
    plog_notice(plugin, "read uuid:%s, group:%s, node:%s", mqtt->uuid,
                req->group, req->node);

    neu_reqresp_head_t header = { 0 };
    header.ctx                = mqtt;
    header.type               = NEU_REQ_READ_GROUP;
    neu_req_read_group_t cmd  = { 0 };
    cmd.driver                = req->node;
    cmd.group                 = req->group;
    cmd.sync                  = req->sync;
    req->node                 = NULL; // ownership moved
    req->group                = NULL; // ownership moved
    if (0 != neu_plugin_op(plugin, header, &cmd)) {
        neu_req_read_group_fini(&cmd);
        plog_error(plugin, "neu_plugin_op(NEU_REQ_READ_GROUP) fail");
        return -1;
    }

    return 0;
}

static int json_value_to_tag_value(union neu_json_value *req,
                                   enum neu_json_type t, neu_dvalue_t *value)
{
    switch (t) {
    case NEU_JSON_INT:
        value->type      = NEU_TYPE_INT64;
        value->value.u64 = req->val_int;
        break;
    case NEU_JSON_STR:
        value->type = NEU_TYPE_STRING;
        strncpy(value->value.str, req->val_str, sizeof(value->value.str));
        break;
    case NEU_JSON_DOUBLE:
        value->type      = NEU_TYPE_DOUBLE;
        value->value.d64 = req->val_double;
        break;
    case NEU_JSON_BOOL:
        value->type          = NEU_TYPE_BOOL;
        value->value.boolean = req->val_bool;
        break;
    case NEU_JSON_BYTES:
        value->type               = NEU_TYPE_BYTES;
        value->value.bytes.length = req->val_bytes.length;
        memcpy(value->value.bytes.bytes, req->val_bytes.bytes,
               req->val_bytes.length);
        break;
    default:
        return -1;
    }
    return 0;
}

static int send_write_tag_req(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt,
                              neu_json_write_req_t *req)
{
    plog_notice(plugin, "write tag uuid:%s, group:%s, node:%s", mqtt->uuid,
                req->group, req->node);

    neu_reqresp_head_t  header = { 0 };
    neu_req_write_tag_t cmd    = { 0 };

    header.ctx  = mqtt;
    header.type = NEU_REQ_WRITE_TAG;

    cmd.driver = req->node;
    cmd.group  = req->group;
    cmd.tag    = req->tag;

    if (0 != json_value_to_tag_value(&req->value, req->t, &cmd.value)) {
        plog_error(plugin, "invalid tag value type: %d", req->t);
        return -1;
    }

    if (0 != neu_plugin_op(plugin, header, &cmd)) {
        plog_error(plugin, "neu_plugin_op(NEU_REQ_WRITE_TAG) fail");
        return -1;
    }

    req->node  = NULL; // ownership moved
    req->group = NULL; // ownership moved
    req->tag   = NULL; // ownership moved
    return 0;
}

static int send_write_tags_req(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt,
                               neu_json_write_tags_req_t *req)
{
    plog_notice(plugin, "write tags uuid:%s, group:%s, node:%s", mqtt->uuid,
                req->group, req->node);

    for (int i = 0; i < req->n_tag; i++) {
        if (req->tags[i].t == NEU_JSON_STR) {
            if (strlen(req->tags[i].value.val_str) >= NEU_VALUE_SIZE) {
                return -1;
            }
        }
    }

    neu_reqresp_head_t header = {
        .ctx  = mqtt,
        .type = NEU_REQ_WRITE_TAGS,
    };

    neu_req_write_tags_t cmd = { 0 };
    cmd.driver               = req->node;
    cmd.group                = req->group;
    cmd.n_tag                = req->n_tag;
    cmd.tags                 = calloc(cmd.n_tag, sizeof(neu_resp_tag_value_t));
    if (NULL == cmd.tags) {
        return -1;
    }

    for (int i = 0; i < cmd.n_tag; i++) {
        strcpy(cmd.tags[i].tag, req->tags[i].tag);
        if (0 !=
            json_value_to_tag_value(&req->tags[i].value, req->tags[i].t,
                                    &cmd.tags[i].value)) {
            plog_error(plugin, "invalid tag value type: %d", req->tags[i].t);
            free(cmd.tags);
            return -1;
        }
    }

    if (0 != neu_plugin_op(plugin, header, &cmd)) {
        plog_error(plugin, "neu_plugin_op(NEU_REQ_WRITE_TAGS) fail");
        free(cmd.tags);
        return -1;
    }

    req->node  = NULL; // ownership moved
    req->group = NULL; // ownership moved

    return 0;
}

// static void publish_cb(int errcode, neu_mqtt_qos_e qos, char *topic,
//                       uint8_t *payload, uint32_t len, void *data)
//{
//    (void) qos;
//    (void) topic;
//    (void) len;
//
//    neu_plugin_t *plugin = data;
//
//    if (0 == errcode) {
//        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_SEND_MSGS_TOTAL, 1, NULL);
//        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_SEND_BYTES_5S, len, NULL);
//        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_SEND_BYTES_30S, len,
//        NULL); NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_SEND_BYTES_60S,
//        len, NULL);
//    } else {
//        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_SEND_MSG_ERRORS_TOTAL, 1,
//                                 NULL);
//    }
//
//    free(payload);
// }
//
// static inline int publish(neu_plugin_t *plugin, neu_mqtt_qos_e qos, char
// *topic,
//                          char *payload, size_t payload_len)
//{
//
//    int rv =
//        neu_mqtt_client_publish(plugin->client, qos, topic, (uint8_t *)
//        payload,
//                                (uint32_t) payload_len, plugin, publish_cb);
//    if (0 != rv) {
//        plog_error(plugin, "pub [%s, QoS%d] fail", topic, qos);
//        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_SEND_MSG_ERRORS_TOTAL, 1,
//                                 NULL);
//        free(payload);
//        rv = NEU_ERR_MQTT_PUBLISH_FAILURE;
//    }
//
//    return rv;
// }
//
// void handle_write_req(neu_mqtt_qos_e qos, const char *topic,
//                      const uint8_t *payload, uint32_t len, void *data)
//{
//    int               rv     = 0;
//    neu_plugin_t *    plugin = data;
//    neu_json_write_t *req    = NULL;
//
//    (void) qos;
//    (void) topic;
//
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_MSGS_TOTAL, 1, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_BYTES_5S, len, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_BYTES_30S, len, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_BYTES_60S, len, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_MSGS_5S, 1, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_MSGS_30S, 1, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_MSGS_60S, 1, NULL);
//
//    char *json_str = malloc(len + 1);
//    if (NULL == json_str) {
//        return;
//    }
//
//    memcpy(json_str, payload, len);
//    json_str[len] = '\0';
//
//    neu_json_mqtt_t *mqtt = NULL;
//    rv                    = neu_json_decode_mqtt_req(json_str, &mqtt);
//    if (0 != rv) {
//        plog_error(plugin, "neu_json_decode_mqtt_req failed");
//        free(json_str);
//        return;
//    }
//
//    rv = neu_json_decode_write(json_str, &req);
//    if (0 != rv) {
//        plog_error(plugin, "neu_json_decode_write fail");
//        neu_json_decode_mqtt_req_free(mqtt);
//        free(json_str);
//        return;
//    }
//
//    if (req->singular) {
//        rv = send_write_tag_req(plugin, mqtt, &req->single);
//    } else {
//        rv = send_write_tags_req(plugin, mqtt, &req->plural);
//    }
//    if (0 != rv) {
//        neu_json_decode_mqtt_req_free(mqtt);
//    }
//
//    neu_json_decode_write_free(req);
//    free(json_str);
// }
//
// int handle_write_response(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt_json,
//                          neu_resp_error_t *data)
//{
//    int   rv       = 0;
//    char *json_str = NULL;
//
//    if (NULL == plugin->client) {
//        rv = NEU_ERR_MQTT_IS_NULL;
//        goto end;
//    }
//
//    if (0 == plugin->config.cache &&
//        !neu_mqtt_client_is_connected(plugin->client)) {
//        // cache disable and we are disconnected
//        rv = NEU_ERR_MQTT_FAILURE;
//        goto end;
//    }
//
//    json_str = generate_write_resp_json(plugin, mqtt_json, data);
//    if (NULL == json_str) {
//        plog_error(plugin, "generate write resp json fail, uuid:%s",
//                   mqtt_json->uuid);
//        rv = NEU_ERR_EINTERNAL;
//        goto end;
//    }
//
//    char *         topic = plugin->config.write_resp_topic;
//    neu_mqtt_qos_e qos   = plugin->config.qos;
//    rv       = publish(plugin, qos, topic, json_str, strlen(json_str));
//    json_str = NULL;
//
// end:
//    neu_json_decode_mqtt_req_free(mqtt_json);
//    return rv;
// }
//
// void handle_read_req(neu_mqtt_qos_e qos, const char *topic,
//                     const uint8_t *payload, uint32_t len, void *data)
//{
//    int                  rv     = 0;
//    neu_plugin_t *       plugin = data;
//    neu_json_read_req_t *req    = NULL;
//
//    (void) qos;
//    (void) topic;
//
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_MSGS_TOTAL, 1, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_BYTES_5S, len, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_BYTES_30S, len, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_BYTES_60S, len, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_MSGS_5S, 1, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_MSGS_30S, 1, NULL);
//    NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_RECV_MSGS_60S, 1, NULL);
//
//    char *json_str = malloc(len + 1);
//    if (NULL == json_str) {
//        return;
//    }
//
//    memcpy(json_str, payload, len);
//    json_str[len] = '\0';
//
//    neu_json_mqtt_t *mqtt = NULL;
//    rv                    = neu_json_decode_mqtt_req(json_str, &mqtt);
//    if (0 != rv) {
//        plog_error(plugin, "neu_json_decode_mqtt_req failed");
//        free(json_str);
//        return;
//    }
//
//    rv = neu_json_decode_read_req(json_str, &req);
//    if (0 != rv) {
//        plog_error(plugin, "neu_json_decode_read_req fail");
//        neu_json_decode_mqtt_req_free(mqtt);
//        free(json_str);
//        return;
//    }
//
//    rv = send_read_req(plugin, mqtt, req);
//    if (0 != rv) {
//        neu_json_decode_mqtt_req_free(mqtt);
//    }
//
//    neu_json_decode_read_req_free(req);
//    free(json_str);
// }

int handle_read_response(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt_json,
                         neu_resp_read_group_t *data)
{
    int   rv       = 0;
    char *json_str = NULL;

    if (NULL == plugin->client) {
        rv = NEU_ERR_MQTT_IS_NULL;
        goto end;
    }

    if (0 == plugin->config.cache &&
        !neu_mqtt_client_is_connected(plugin->client)) {
        // cache disable and we are disconnected
        rv = NEU_ERR_MQTT_FAILURE;
        goto end;
    }

    json_str = generate_read_resp_json(plugin, mqtt_json, data);
    if (NULL == json_str) {
        plog_error(plugin, "generate read resp json fail");
        rv = NEU_ERR_EINTERNAL;
        goto end;
    }

    char          *topic = plugin->read_resp_topic;
    neu_mqtt_qos_e qos   = plugin->config.qos;
    rv       = publish(plugin, qos, topic, json_str, strlen(json_str));
    json_str = NULL;

end:
    neu_json_decode_mqtt_req_free(mqtt_json);
    return rv;
}

int handle_trans_data(neu_plugin_t             *plugin,
                      neu_reqresp_trans_data_t *trans_data)
{

    int ret = 0;
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
    int rv = 0;

    neu_json_elem_t topic = { .name = "topic", .t = NEU_JSON_STR };
    if (NULL == sub_info->params) {
        // no parameters, try default topic
        topic.v.val_str = default_upload_topic(sub_info);
        if (NULL == topic.v.val_str) {
            rv = NEU_ERR_EINTERNAL;
            goto end;
        }
    } else if (0 != neu_parse_param(sub_info->params, NULL, 1, &topic)) {
        plog_error(plugin, "parse `%s` for topic fail", sub_info->params);
        rv = NEU_ERR_GROUP_PARAMETER_INVALID;
        goto end;
    }

    rv = route_tbl_add_new(&plugin->route_tbl, sub_info->driver,
                           sub_info->group, topic.v.val_str);
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

    rv = route_tbl_update(&plugin->route_tbl, sub_info->driver, sub_info->group,
                          topic.v.val_str);
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
    route_tbl_del(&plugin->route_tbl, unsub_info->driver, unsub_info->group);
    plog_notice(plugin, "del route driver:%s group:%s", unsub_info->driver,
                unsub_info->group);
    return 0;
}

int handle_update_group(neu_plugin_t *plugin, neu_req_update_group_t *req)
{
    route_tbl_update_group(&plugin->route_tbl, req->driver, req->group,
                           req->new_name);
    plog_notice(plugin, "update route driver:%s group:%s to %s", req->driver,
                req->group, req->new_name);
    return 0;
}

int handle_update_driver(neu_plugin_t *plugin, neu_req_update_node_t *req)
{
    route_tbl_update_driver(&plugin->route_tbl, req->node, req->new_name);
    plog_notice(plugin, "update route driver:%s to %s", req->node,
                req->new_name);
    return 0;
}

int handle_del_driver(neu_plugin_t *plugin, neu_reqresp_node_deleted_t *req)
{
    route_tbl_del_driver(&plugin->route_tbl, req->node);
    plog_notice(plugin, "delete route driver:%s", req->node);
    return 0;
}
