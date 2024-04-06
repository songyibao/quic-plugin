#include "client.h"
#include "message.h"
#include "mysqlite.h"
#include "quic.h"
#include "zlib.h"
#include <arpa/inet.h>
#include <cjson/cJSON.h>

typedef struct watcher_data {
    neu_plugin_t *plugin;
    int           sock_index;
} watcher_data_t;

typedef struct keep_alive_data {
    neu_plugin_t *plugin;
    quic_conn_t * conn;
} keep_alive_data_t;




int send_data(neu_plugin_t *plugin,quic_conn_t *conn,uint64_t stream_id,int
*fin)
{
    plog_debug(plugin, "start to send data to server");
    int   ret = 0;
    char *data_json_str =
        read_records(plugin->db, plugin->table_name, plugin->msg_buffer_size);
    if(strcmp(data_json_str,"[]")==0){
        plog_debug(plugin,"no data to send");
        cJSON_free(data_json_str);
        ret=-1;
        goto error;
    }
    plog_debug(plugin, "parse json str succeed: %s", data_json_str);
    Message quic_message  = create_message(SendDataRequest, "transferring data",
                                           SEND_DATA, data_json_str);
    char   *json_str      = serialize_message(&quic_message);
    size_t  json_str_size = strlen(json_str) + 1;
    plog_debug(plugin, "压缩前的数据bit数：8 * %lu = %lu:", json_str_size,
                json_str_size * 8);

    unsigned char *compressed_str;
    size_t         compressed_size;

    // 压缩
    if (compress_string((const char *) json_str, &compressed_str,
                        &compressed_size) == -1) {
        ret = -2;
        goto error;
                        }
    if(quic_stream_write(conn, stream_id, (uint8_t *) compressed_str,
    compressed_size,
                      true)!=compressed_size) {
        plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
        ret=-3;
        goto error;
    }
    *fin = 1;

    plog_debug(plugin, "压缩后的数据bit数：8 * %lu = %lu:", compressed_size,
                compressed_size * 8);
    plog_debug(plugin,
                "压缩比例：%.2f:", 1.0 * compressed_size / json_str_size);

    free(compressed_str);

    // 与"free(quic_message.data);
    // "同效用，释放的是同一块内存，因为其指向真实的生产数据，数据量可能过大，不适合再进行内存拷贝，所以"create_message
    // "函数直接使用了传入的指针，即不再进行内存拷贝，所以在释放"quic_message.data"时，也会释放"json_str"指向的内存
    free(data_json_str);

    free(json_str);
    return 0;
error:
    return ret;
}
void client_on_stream_closed(void *   tctx, quic_conn_t *conn,
                             uint64_t stream_id)
{
    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "client_on_stream_closed,stream id%ld", stream_id);
}

void client_on_conn_closed(void *tctx, struct quic_conn_t *conn)
{
    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "client_on_conn_closed");
    // 停止并释放watcher
    for (int i = 0; i < plugin->ip_count; i++) {
        if(conn != plugin->conns[i]){
            continue;
        }
        ev_io *watcher = plugin->ev_watchers[i];/* 你需要有某种方式来引用或存储每个创建的watcher */;
        ev_io_stop(plugin->loop, watcher);
        watcher_data_t *watcher_data = (watcher_data_t *)watcher->data;

        // 如果有必要，释放watcher_data内部的资源

        free(watcher_data); // 释放watcher_data
        free(watcher); // 释放watcher
        break;
    }
}

void client_on_conn_created(void *tctx, quic_conn_t *conn)
{

    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "client_on_conn_created)");
    // quic_stream_wantwrite(conn, 0, true);

}

void client_on_conn_established(void *tctx, quic_conn_t *conn)
{
    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "client_on_conn_established");
    // // id 0 is reserved for keepalive
    // quic_stream_new(conn, 0, 1, true);
    // // id 1 is reserved for data
    // quic_stream_new(conn, 1, 100, true);
    quic_stream_new(conn,0,10,true);
    quic_stream_wantwrite(conn, 0, true);


}


void client_on_stream_created(void *   tctx, quic_conn_t *conn,
                              uint64_t stream_id)
{
    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "client_on_stream_created,stream id%ld", stream_id);
    // quic_stream_wantwrite(conn, stream_id,true);
}

void client_on_stream_readable(void *   tctx, quic_conn_t *conn,
                               uint64_t stream_id)
{
    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "client_on_stream_readable");
    static uint8_t buf[READ_BUF_SIZE];
    bool fin = false;
    ssize_t r = quic_stream_read(conn, stream_id, buf, READ_BUF_SIZE, &fin);
    if (r < 0) {
        fprintf(stderr, "stream[%ld] read error\n", stream_id);
        return;
    }
    cJSON *json_data   = cJSON_Parse(buf);
    if(json_data ==NULL) {
        plog_debug(plugin,"json parse failed,close conn");
        const char *reason = "ok";
        quic_conn_close(conn, true, 0, (const uint8_t *) reason,
                        strlen(reason));
    }
    int    status_code = cJSON_GetObjectItem(json_data, "status")->valueint;
    // switch status_code
    switch (status_code) {
    case HELLO:
        plog_debug(plugin,"server response hello");
        plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
        break;
    case SEND_DATA:
        break;
    default:
        cJSON_free(json_data);
        break;
    }
    if (fin) {
        plog_debug(plugin,"stream[%ld] read fin,close conn", stream_id);
        const char *reason = "ok";
        quic_conn_close(conn, true, 0, (const uint8_t *) reason,
                        strlen(reason));
        // by default, node is connected after connection try
    }
}
void client_on_stream_writable(void *   tctx, quic_conn_t *conn,
                               uint64_t stream_id)
{
    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "client_on_stream_writable,stream id%ld", stream_id);
    unsigned char *compressed;
    size_t compressed_size = 0;
    char *message = quic_conn_context(conn);

    if(plugin->common.link_state == NEU_NODE_LINK_STATE_DISCONNECTED){
        Message hello_msg = create_message(HelloRequest, message, HELLO, "[]");
        char *data = serialize_message(&hello_msg);
        assert(compress_string(data, (unsigned char **) &compressed, &compressed_size) == Z_OK);
        if(quic_stream_write(conn,stream_id, compressed, compressed_size, false)
         == compressed_size) {
            plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
        }
    }else {
        char error_message[30];
        int fin=0;
        int ret = send_data(plugin,conn,stream_id,&fin);
        if(ret==-3){
            plog_error(plugin,"fatal error,send data failed");
            plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
        }else {
            if(fin==0) {
                if(ret == -1) {
                    strcpy(error_message,"NoDataToSend");
                }else {
                    strcpy(error_message,"CompressError");
                }
                Message data_msg = create_message(SendDataRequest,
                error_message,
SEND_DATA, "[]");
                char *data = serialize_message(&data_msg);
                assert(compress_string(data, (unsigned char **) &compressed, &compressed_size) == Z_OK);
                if(quic_stream_write(conn,stream_id, compressed, compressed_size,
                 true)
                 == compressed_size) {
                    plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
                 }
            }else {
                plog_debug(plugin,"Unknow error");
            }
        }
    }
    // quic_stream_shutdown(conn,stream_id,1,0);
    quic_stream_wantwrite(conn, stream_id, false);
    // quic_stream_wantread(conn, stream_id, true);
}
int client_on_packets_send(void *       psctx, quic_packet_out_spec_t *pkts,
                           unsigned int count)
{

    neu_plugin_t *plugin = psctx;
    plog_debug(plugin, "client_on_packets_send");
    unsigned int sent_count = 0;
    for (int i = 0; i < count; i++) {
        // fprintf(stdout, "quic packet %d\n", i);
        quic_packet_out_spec_t *pkt = pkts + i;
        struct sockaddr_in *tmp_sin_addr = (struct sockaddr_in *) pkt->src_addr;
        for (int j = 0; j < pkt->iovlen; j++) {
            // fprintf(stdout, "iov %d\n", j);
            // printf("数据包出站地址：%s\n",
            //        inet_ntoa(tmp_sin_addr->sin_addr));
            // printf("数据包出站端口：%d\n",
            //        ntohs(tmp_sin_addr->sin_port));
            // printf("数据包长度：%lu\n", pkt->iov[j].iov_len);

            for (int k = 0; k < plugin->ip_count; k++) {
                if (plugin->local_addr[k].sin_addr.s_addr == tmp_sin_addr->
                    sin_addr.s_addr) {
                    const struct iovec *iov  = pkt->iov + j;
                    ssize_t             sent =
                        sendto(plugin->sock[k], iov->iov_base, iov->iov_len, 0,
                               (struct sockaddr *) pkt->dst_addr,
                               pkt->dst_addr_len);

                    if (sent != iov->iov_len) {
                        if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                            fprintf(
                                stderr, "send would block, already sent: %d\n",
                                sent_count);
                            return sent_count;
                        }
                        return -1;
                    }
                    sent_count++;
                    break;
                }
            }
        }
    }

    return sent_count;
}

char s_alpn[0x100];

int add_alpn(const char *alpn)
{
    size_t alpn_len, all_len;

    alpn_len = strlen(alpn);
    if (alpn_len > 255)
        return -1;

    all_len = strlen(s_alpn);
    if (all_len + 1 + alpn_len + 1 > sizeof(s_alpn))
        return -1;

    s_alpn[all_len] = alpn_len;
    memcpy(&s_alpn[all_len + 1], alpn, alpn_len);
    s_alpn[all_len + 1 + alpn_len] = '\0';
    return 0;
}

int client_load_ssl_ctx(neu_plugin_t *plugin)
{
    add_alpn("http/0.9");
    plugin->ssl_ctx = SSL_CTX_new(TLS_method());
    if (SSL_CTX_set_default_verify_paths(plugin->ssl_ctx) != 1) {
        fprintf(stderr, "set default verify path failed\n");
        return -1;
    }
    if (SSL_CTX_set_alpn_protos(plugin->ssl_ctx, (const unsigned char *) s_alpn,
                                strlen(s_alpn)) != 0) {
        fprintf(stderr, "set alpn failed\n");
        return -1;
    }

    return 0;
}

void process_connections(neu_plugin_t *plugin)
{
    quic_endpoint_process_connections(plugin->quic_endpoint);
    double timeout = quic_endpoint_timeout(plugin->quic_endpoint) / 1e3f;
    if (timeout < 0.0001) {
        timeout = 0.0001;
    }
    plugin->ev_timer.repeat = timeout;
    ev_timer_again(plugin->loop, &plugin->ev_timer);
}

void read_callback(EV_P_ ev_io *w, int revents)
{
    watcher_data_t *data       = w->data;
    neu_plugin_t *  plugin     = data->plugin;
    int             sock_index = data->sock_index;
    fprintf(stdout, "%d:read_callback\n", sock_index);
    static uint8_t buf[READ_BUF_SIZE];

    while (true) {
        struct sockaddr_storage peer_addr;
        socklen_t               peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(plugin->sock[sock_index], buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr, &peer_addr_len);
        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                break;
            }

            fprintf(stderr, "failed to read\n");
            return;
        }

        quic_packet_info_t quic_packet_info = {
            .src = (struct sockaddr *) &peer_addr,
            .src_len = peer_addr_len,
            .dst = (struct sockaddr *) &plugin->local_addr[sock_index],
            .dst_len = plugin->local_addr_len[sock_index],
        };

        int r =
            quic_endpoint_recv(plugin->quic_endpoint, buf, read,
                               &quic_packet_info);
        if (r != 0) {
            fprintf(stderr, "recv failed %d\n", r);
        }
    }
    process_connections(plugin);
}

void example_timeout_callback(EV_P_ ev_timer *w, int revents)
{
    neu_plugin_t *plugin = w->data;
    quic_endpoint_on_timeout(plugin->quic_endpoint);
    process_connections(plugin);
}

void debug_log(const unsigned char *line, void *argp)
{
    fprintf(stderr, "%s\n", line);
}

int create_socket(const char *      host, const char *  port,
                  struct addrinfo **peer, neu_plugin_t *plugin)
{
    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };
    if (getaddrinfo(host, port, &hints, peer) != 0) {
        fprintf(stderr, "failed to resolve host\n");
        return -1;
    }

    for (int i = 0; i < plugin->ip_count; i++) {
        plugin->sock[i] = socket((*peer)->ai_family, SOCK_DGRAM, 0);
        if (plugin->sock[i] < 0) {
            fprintf(stderr, "failed to create socket %d\n", i);
            return -1;
        }
        if (fcntl(plugin->sock[i], F_SETFL, O_NONBLOCK) != 0) {
            fprintf(stderr, "failed to make socket non-blocking %d\n", i);
            return -1;
        }
        struct sockaddr_in local_addr;
        local_addr.sin_family      = AF_INET;
        local_addr.sin_addr.s_addr = inet_addr(plugin->ips[i]);
        local_addr.sin_port        = htons(44990 + i);
        if (bind(plugin->sock[i], (struct sockaddr *) &local_addr,
                 sizeof(local_addr)) < 0) {
            perror("bind failed");
            return -1;
        }
        // 让client->local_addr[i]的值等于local_addr
        plugin->local_addr[i]     = local_addr;
        plugin->local_addr_len[i] = sizeof(local_addr);
        fprintf(stdout, "%d:Successfully bound to %s:%d\n", i,
                inet_ntoa(plugin->local_addr[i].sin_addr),
                ntohs(plugin->local_addr[i].sin_port));
    }
    return 0;
}

// 压缩 JSON 字符串
int compress_string(const char *str, unsigned char **compressed,
                    size_t *    compressed_size)
{
    uLong str_length  = strlen(str) + 1;           // 包括终止符
    uLong comp_length = compressBound(str_length); // 计算压缩后的最大长度

    // 分配压缩缓冲区
    *compressed = (unsigned char *) malloc(comp_length + sizeof(uLong));
    if (*compressed == NULL) {
        return -1;
    }
    memcpy(*compressed, &str_length, sizeof(uLong));
    // 压缩
    if (compress(*compressed + sizeof(uLong), &comp_length,
                 (const unsigned char *) str, str_length) != Z_OK) {
        free(*compressed);
        return -1;
    }

    *compressed_size = comp_length + sizeof(uLong);
    return 0;
}
void send_keepalive(EV_P_ ev_timer *w, int revents)
{
    neu_plugin_t *plugin = w->data;
    plog_debug(plugin, "send keepalive");
    // Connect to server.
    plog_debug(plugin, "Connecting to server");
    for (int i = 0; i < plugin->ip_count; i++) {

        uint64_t conn_index = -1;
        plog_debug(plugin, "第%d个连接", i);
        int ret = quic_endpoint_connect(plugin->quic_endpoint,
                                        (struct sockaddr *) &plugin->local_addr[
                                            i], plugin->local_addr_len[i],
                                        plugin->peer->ai_addr,
                                        plugin->peer->ai_addrlen,
                                        NULL /* client_name*/,
                                        NULL /* session */, 0 /* session_len */,
                                        NULL /* token */, 0 /* token_len */,
                                        &conn_index);

        if (ret < 0) {
            plog_error(plugin, "new conn failed: %d\n", ret);
        }
        plog_debug(plugin, "new conn index: %ld\n", conn_index);
        plugin->conns[i] = quic_endpoint_get_connection(plugin->quic_endpoint,
            conn_index);
        quic_conn_set_context(plugin->conns[i],plugin->ips[i]);
    }
    process_connections(plugin);
    plog_debug(plugin, "Start event loop");
    for (int i = 0; i < plugin->ip_count; i++) {
        watcher_data_t *watcher_data = malloc(sizeof(watcher_data_t));
        watcher_data->plugin         = plugin;
        watcher_data->sock_index     = i;
        ev_io *watcher               = malloc(sizeof(struct ev_io));
        ev_io_init(watcher, read_callback, plugin->sock[i], EV_READ);
        ev_io_start(plugin->loop, watcher);
        watcher->data = watcher_data;
        plugin->ev_watchers[i] = watcher;
    }


    // keep_alive_data_t *arg = w->data;
    // neu_plugin_t *     plugin = arg->plugin;
    // quic_conn_t *      conn   = arg->conn;
    //
    // // 注意：静态分配的字符串不能用free释放，所以这里不调用free_message函数
    // Message hello_msg = create_message(HelloRequest, "KeepAlive", HELLO, "[]");
    //
    // char *         data = serialize_message(&hello_msg);
    // unsigned char *compressed;
    // size_t         compressed_size = 0;
    // assert(compress_string(data, &compressed, &compressed_size) == Z_OK);
    // ssize_t res_size = quic_stream_write(conn, 0, compressed, compressed_size,
    //                                      false);
    // nlog_debug("res_size:%ld,compressed_size:%ld", res_size, compressed_size);
    // if (res_size != compressed_size) {// 发送失败
    //     plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    //     fprintf(stderr, "failed to send keepalive\n");
    // }
    // free(data);
    // free(compressed);
}
const struct quic_transport_methods_t local_quic_transport_methods = {
    .on_conn_created = client_on_conn_created,
    .on_conn_established = client_on_conn_established,
    .on_conn_closed = client_on_conn_closed,
    .on_stream_created = client_on_stream_created,
    .on_stream_readable = client_on_stream_readable,
    .on_stream_writable = client_on_stream_writable,
    .on_stream_closed = client_on_stream_closed,
};

const struct quic_packet_send_methods_t local_quic_packet_send_methods = {
    .on_packets_send = client_on_packets_send,
};

int create_quic_config(neu_plugin_t *plugin)
{
    // Create quic config.
    quic_config_t *config = quic_config_new();
    if (config == NULL) {
        return -1;
    }
    quic_config_set_max_idle_timeout(config, 5000);
    quic_config_set_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);

    // Create and set tls config.
    if (client_load_ssl_ctx(plugin) != 0) {
        plog_error(plugin, "failed to load ssl ctx\n");
        return -1;
    }
    quic_config_set_tls_config(config, plugin->ssl_ctx);
    plugin->config = config;
    return 0;
}

int create_quic_endpoint(neu_plugin_t *plugin)
{
    // Create quic endpoint
    plugin->quic_endpoint =
        quic_endpoint_new(plugin->config, false, &local_quic_transport_methods,
                          plugin, &local_quic_packet_send_methods, plugin);
    if (plugin->quic_endpoint == NULL) {
        return -1;
    }
    return 0;
}

int init_event_loop(neu_plugin_t *plugin)
{
    // Init event loop.
    plugin->loop = ev_loop_new(0);
    ev_init(&plugin->ev_timer, example_timeout_callback);
    plugin->ev_timer.data = plugin;
    if (plugin->loop == NULL || plugin->ev_timer.data == NULL) {
        return -1;
    }
    return 0;
}


int start_quic_client(neu_plugin_t *plugin)
{

    plugin->quic_endpoint = NULL;
    plugin->ssl_ctx       = NULL;
    plugin->loop          = NULL;
    plugin->config        = NULL;
    plugin->peer          = NULL;
    for (int i = 0; i < MAX_IPS; i++) {
        plugin->sock[i]  = -1;
        plugin->conns[i] = NULL;
    }

    plog_debug(plugin, "Starting quic client");
    //create socket
    plog_debug(plugin, "Creating socket");
    if (create_socket(plugin->host, plugin->port, &plugin->peer, plugin) != 0) {
        plog_error(plugin, "failed to create socket\n");
        goto EXIT;
    }
    plog_debug(plugin, "peer addr: %s",
               inet_ntoa(((struct sockaddr_in *) plugin->peer->ai_addr)->
                   sin_addr));
    // set config
    plog_debug(plugin, "Setting quic config");
    if (create_quic_config(plugin) != 0) {
        plog_error(plugin, "failed to create quic config\n");
        goto EXIT;
    }
    // create quic endpoint
    plog_debug(plugin, "creating quic endpoint");
    if (create_quic_endpoint(plugin) != 0) {
        plog_error(plugin, "failed to create quic endpoint\n");
        goto EXIT;
    }
    if (init_event_loop(plugin) != 0) {
        plog_error(plugin, "failed to init event loop\n");
        goto EXIT;
    }
    // // Connect to server.
    // plog_debug(plugin, "Connecting to server");
    // for (int i = 0; i < plugin->ip_count; i++) {
    //
    //     uint64_t conn_index = -1;
    //     plog_debug(plugin, "第%d个连接", i);
    //     int ret = quic_endpoint_connect(plugin->quic_endpoint,
    //                                     (struct sockaddr *) &plugin->local_addr[
    //                                         i], plugin->local_addr_len[i],
    //                                     plugin->peer->ai_addr,
    //                                     plugin->peer->ai_addrlen,
    //                                     NULL /* client_name*/,
    //                                     NULL /* session */, 0 /* session_len */,
    //                                     NULL /* token */, 0 /* token_len */,
    //                                     &conn_index);
    //     plog_debug(plugin, "conn_index: %ld\n", conn_index);
    //     if (ret < 0) {
    //         plog_error(plugin, "new conn failed: %d\n", ret);
    //         goto EXIT;
    //     }
    //     plog_debug(plugin, "new conn index: %ld\n", conn_index);
    //     // process_connections(plugin);
    //     plugin->conns[i] = quic_endpoint_get_connection(plugin->quic_endpoint,
    //         conn_index);
    // }
    // process_connections(plugin);
    //
    // plog_debug(plugin, "Start event loop");
    // for (int i = 0; i < plugin->ip_count; i++) {
    //     watcher_data_t *watcher_data = malloc(sizeof(watcher_data_t));
    //     watcher_data->plugin         = plugin;
    //     watcher_data->sock_index     = i;
    //     ev_io *watcher               = malloc(sizeof(struct ev_io));
    //     ev_io_init(watcher, read_callback, plugin->sock[i], EV_READ);
    //     ev_io_start(plugin->loop, watcher);
    //     watcher->data = watcher_data;
    // }
    // 初始化和启动保活定时器
    ev_timer *keepalive_timer = malloc(sizeof(ev_timer));
    ev_timer_init(keepalive_timer, send_keepalive, 5.0, 5.0); // 每5秒发送一次保活包
    keepalive_timer->data = plugin;
    ev_timer_start(plugin->loop, keepalive_timer);

    // Start event loop.
    ev_loop(plugin->loop, 0);

EXIT:
    if (plugin->peer != NULL) {
        freeaddrinfo(plugin->peer);
    }
    if (plugin->ssl_ctx != NULL) {
        SSL_CTX_free(plugin->ssl_ctx);
    }
    // 循环关闭所有的socket
    for (int i = 0; i < plugin->ip_count; i++) {
        if (plugin->sock[i] > 0) {
            close(plugin->sock[i]);
        }
    }
    if (plugin->quic_endpoint != NULL) {
        quic_endpoint_free(plugin->quic_endpoint);
    }
    if (plugin->loop != NULL) {
        ev_loop_destroy(plugin->loop);
    }
    if (plugin->config != NULL) {
        quic_config_free(plugin->config);
    }
    return -1;
}