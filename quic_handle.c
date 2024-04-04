#include <utils/asprintf.h>

#include "client.h"
#include "json_rw.h"
#include "message.h"
#include "mysqlite.h"
#include "neuron.h"
#include "plugin.h"
#include "quic.h"
#include "quic_handle.h"
#include "quic_utils.h"
#include <cjson/cJSON.h>

static neu_reqresp_trans_data_t *local_trans_data;

#define CHUNK_SIZE 16384 // 定义缓冲区大小

int parse_send_data(neu_plugin_t *plugin, quic_conn_t *conn,
                    neu_reqresp_trans_data_t *trans_data)
{
    plog_notice(plugin, "start to send data to server");
    int   ret = 0;
    char *data_json_str =
        read_records(plugin->db, plugin->table_name, plugin->msg_buffer_size);
    plog_notice(plugin, "parse json str succeed: %s", data_json_str);
    Message quic_message  = create_message(SendDataRequest, "transferring data",
                                           SEND_DATA, data_json_str);
    char   *json_str      = serialize_message(&quic_message);
    size_t  json_str_size = strlen(json_str) + 1;
    plog_notice(plugin, "压缩前的数据bit数：8 * %lu = %lu:", json_str_size,
                json_str_size * 8);

    unsigned char *compressed_str;
    size_t         compressed_size;

    // 压缩
    if (compress_string((const char *) json_str, &compressed_str,
                        &compressed_size) == -1) {
        ret = -1;
        goto error;
    }
    quic_stream_write(conn, 0, (uint8_t *) compressed_str, compressed_size,
                      true);

    plog_notice(plugin, "压缩后的数据bit数：8 * %lu = %lu:", compressed_size,
                compressed_size * 8);
    plog_notice(plugin,
                "压缩比例：%.2f:", 1.0 * compressed_size / json_str_size);

    free(compressed_str);

    // 与"free(quic_message.data);
    // "同效用，释放的是同一块内存，因为其指向真实的生产数据，数据量可能过大，不适合再进行内存拷贝，所以"create_message
    // "函数直接使用了传入的指针，即不再进行内存拷贝，所以在释放"quic_message.data"时，也会释放"json_str"指向的内存
    free(data_json_str);

    free(json_str);
    return 0;
error:
    plog_notice(plugin, "压缩失败");
    return ret;
}
void on_conn_established(void *tctx, struct quic_conn_t *conn)
{
    simple_client_t *client = (simple_client_t *) tctx;
    quic_stream_wantwrite(conn, 0, true);
    // Call function to send JSON data
    parse_send_data(client->plugin, conn, local_trans_data);
}
void *thread_trans_data(void *arg)
{
    thread_args_t *local_args = (thread_args_t *) arg;

    new_client(local_args->plugin,example_timeout_callback, on_conn_established);
    return NULL;
}

int handle_read_response(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt_json,
                         neu_resp_read_group_t *data)
{
    int res = 0;
    return res;
}
int handle_insert_data(neu_plugin_t             *plugin,
                       neu_reqresp_trans_data_t *trans_data)
{
    plog_notice(plugin, "start to parse data and insert data to database");
    int              ret      = 0;
    char            *json_str = NULL;
    json_read_resp_t resp     = {
            .plugin     = plugin,
            .trans_data = trans_data,
    };
    ret = neu_json_encode_by_fn(&resp, json_encode_read_resp, &json_str);
    if (ret != 0) {
        plog_notice(plugin, "parse json failed");
        goto error;
    }
    plog_debug(plugin, "parse json str succeed: %s", json_str);
    cJSON *json = cJSON_Parse(json_str);
    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        return 1;
    }

    // 获取"node_name"
    cJSON *node_name = cJSON_GetObjectItemCaseSensitive(json, "node_name");

    // 获取"group_name"
    cJSON *group_name = cJSON_GetObjectItemCaseSensitive(json, "group_name");

    // 获取"timestamp"
    cJSON *timestamp = cJSON_GetObjectItemCaseSensitive(json, "timestamp");

    // 获取"values"
    cJSON *values = cJSON_GetObjectItemCaseSensitive(json, "values");
    //    // 如果values字段为空，不插入该条记录
    //    if(values == NULL || !cJSON_IsObject(values)){
    //        ret = -1;
    //        plog_info(plugin,"plugin data is empty");
    //        goto error;
    //    }

    // 将 "values" 对象转换为 JSON 字符串
    char *values_str_unformatted = cJSON_PrintUnformatted(values);

    cJSON *errors = cJSON_GetObjectItemCaseSensitive(json, "errors");
    // 将 "errors" 对象转换为 JSON 字符串
    char  *errors_str_unformatted = cJSON_PrintUnformatted(errors);
    cJSON *metas = cJSON_GetObjectItemCaseSensitive(json, "metas");
    // 将 "metas" 对象转换为 JSON 字符串
    char *metas_str_unformatted = cJSON_PrintUnformatted(metas);

    ret = insert_data(plugin->db, plugin->table_name, node_name->valuestring,
                      group_name->valuestring, (long) timestamp->valuedouble,
                      values_str_unformatted, errors_str_unformatted,
                      metas_str_unformatted);
    // 清理JSON对象
    cJSON_Delete(json);
    cJSON_free(values_str_unformatted);
    cJSON_free(errors_str_unformatted);
    cJSON_free(metas_str_unformatted);
    return ret;
error:
    return ret;
}
int handle_trans_data(neu_plugin_t             *plugin,
                      neu_reqresp_trans_data_t *trans_data)
{
    int ret          = 0;
    local_trans_data = trans_data;
    new_client(plugin,example_timeout_callback, on_conn_established);
//     for (int i = 0; i < plugin->ip_count; i++) {
//         (plugin->thread_args)[i].plugin          = plugin;
//         (plugin->thread_args)[i].interface_index = i;
//     }
//     // 创建多线程并传递参数
//     for (int i = 0; i < plugin->ip_count; i++) {
//         plog_notice(plugin, "Create thread %d/%d.\n", i + 1, plugin->ip_count);
//         if (pthread_create(&plugin->thread_ids[i], NULL, thread_trans_data,
// &(plugin->thread_args)[i]) !=
//             0) {
//             plog_error(plugin, "Error creating thread %d.\n", i);
//         }
//     }
//
//     local_trans_data = NULL;
//     plog_notice(plugin, "Exit handle_trans_data function");
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
