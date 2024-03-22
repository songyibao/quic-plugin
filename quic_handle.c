#include <utils/asprintf.h>

#include "client.h"
#include "json_rw.h"
#include "neuron.h"
#include "plugin.h"
#include "quic.h"
#include "quic_handle.h"
#include "mysqlite.h"
#include <cjson/cJSON.h>

static neu_reqresp_trans_data_t *local_trans_data;
static ev_io                     watcher;

#define CHUNK_SIZE 16384  // 定义缓冲区大小

int parse_send_data(neu_plugin_t *plugin, quic_conn_t *conn,
                    neu_reqresp_trans_data_t *trans_data)
{
    plog_notice(plugin, "start parse json ");
    int              ret      = 0;
    char            *json_str = read_records(plugin->db,plugin->table_name,0);
    plog_notice(plugin, "parse json str succeed: %s", json_str);
    size_t json_str_size = strlen(json_str)+1;
    plog_notice(plugin,"压缩前的数据bit数：8 * %lu = %lu:",json_str_size,json_str_size*8);
    char* original_str = (char *)malloc(json_str_size);
    memcpy(original_str,json_str,json_str_size);
    unsigned char* compressed_str;
    size_t compressed_size;

    // 压缩
    if(compress_string((const char *)original_str, &compressed_str, &compressed_size) == -1){
        ret = -1;
        goto error;
    }
    quic_stream_write(conn, 0, (uint8_t *) compressed_str, compressed_size, true);



    plog_notice(plugin,"压缩后的数据bit数：8 * %lu = %lu:",compressed_size,compressed_size*8);
    plog_notice(plugin,"压缩比例：%.2f:",1.0*compressed_size/json_str_size);

    quic_stream_write(conn, 0, (uint8_t *) compressed_str, compressed_size, true);
    free(compressed_str);
    free(json_str);
    free(original_str);
    return 0;
error:
    plog_notice(plugin,"压缩失败");
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
int handle_insert_data(neu_plugin_t             *plugin,
                       neu_reqresp_trans_data_t *trans_data){
    plog_notice(plugin, "start parse json ");
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
    plog_notice(plugin, "parse json str succeed: %s", json_str);
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

    // 将 "values" 对象转换为 JSON 字符串
    char *values_str_unformatted = cJSON_PrintUnformatted(values);


    cJSON *errors = cJSON_GetObjectItemCaseSensitive(json, "errors");
    cJSON *metas = cJSON_GetObjectItemCaseSensitive(json, "metas");

    ret = insert_data(plugin->db,plugin->table_name,node_name->valuestring,
                group_name->valuestring,(long)timestamp->valuedouble,
                values_str_unformatted,errors->valuestring,metas->valuestring);
    // 清理JSON对象
    cJSON_Delete(json);
    free(values_str_unformatted);
//    cJSON_Delete(node_name);
//    cJSON_Delete(group_name);
//    cJSON_Delete(timestamp);
//    cJSON_Delete(values);
//    cJSON_Delete(errors);
//    cJSON_Delete(metas);
    return ret;
error:
    return ret;
}
int handle_trans_data(neu_plugin_t             *plugin,
                      neu_reqresp_trans_data_t *trans_data)
{
    int ret          = 0;
    local_trans_data = trans_data;
    local_plugin     = plugin;

    new_client(plugin,example_timeout_callback,on_conn_established);


    // free_client(plugin->client);
    local_plugin     = NULL;
    local_trans_data = NULL;
    plog_notice(plugin, "Exit handle_trans_data function");
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
