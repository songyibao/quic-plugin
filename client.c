#include "client.h"
#include "message.h"
#include "mysqlite.h"
#include "quic.h"
#include "zlib.h"
#include "../../src/daemon.h"

#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <inttypes.h>

typedef struct watcher_data {
    neu_plugin_t *plugin;
    int           sock_index;
} watcher_data_t;

typedef struct keep_alive_data {
    neu_plugin_t *plugin;
    quic_conn_t * conn;
} keep_alive_data_t;


int send_data(neu_plugin_t *plugin, quic_conn_t *conn, uint64_t stream_id)
{
    // 无论如何都要保证有数据发送，否则会一直触发 on_stream_writable 事件
    char    message[40]; // ip, 长度不超过16;其他信息，长度不超过24
    Message quic_message = create_message(SendDataRequest, NULL, SEND_DATA,
                                          NULL);
    char *         json_str        = NULL;
    size_t         json_str_size   = 0;
    unsigned char *compressed_str  = NULL;
    size_t         compressed_size = 0;
    plog_debug(plugin, "Start to send data to server");
    int   ret           = 0;
    char *data_json_str =
        read_records(plugin->db, plugin->table_name, plugin->msg_buffer_size);
    if (strcmp(data_json_str, "[]") == 0) {
        strcpy(message, quic_conn_context(conn)); // 最大16字节
        strcat(message, "EmptyData");             // 9字节
        plog_debug(plugin, "no data to send");
        json_str = new_quic_message_str(SendDataRequest, message,
                                        SEND_DATA, "[]");
        ret = -1;
    } else {
        strcpy(message, quic_conn_context(conn)); // 最大16字节
        plog_debug(plugin, "Sending data to server");
        json_str = new_quic_message_str(SendDataRequest, message, SEND_DATA,
                                        data_json_str);
        ret = 0;
    }
    json_str_size = strlen(json_str) + 1;
    plog_debug(plugin, "parse json str succeed: %s", data_json_str);
    plog_debug(plugin, "压缩前的数据bit数：8 * %lu = %lu:", json_str_size,
               json_str_size * 8);
    // 压缩
    if (compress_string(json_str, &compressed_str, &compressed_size) == -1) {
        plog_error(plugin, "Compress failed");
        json_str = new_quic_message_str(SendDataRequest, "Compress failed",
                                        SEND_DATA,
                                        "[]");
        goto send;
    }

    plog_debug(plugin, "压缩后的数据bit数：8 * %lu = %lu:", compressed_size,
               compressed_size * 8);
    plog_debug(plugin,
               "压缩比例：%.2f:", 1.0 * compressed_size / json_str_size);

send:
    if (quic_stream_write(conn, stream_id, (uint8_t *) compressed_str,
                          compressed_size,
                          true) != compressed_size) {
        plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    } else {
        plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
    }
    if (json_str != NULL) {
        free(json_str);
    }
    if (compressed_str != NULL) {
        free(compressed_str);
    }
    if (data_json_str != NULL) {
        free(data_json_str);
    }
    return ret;
}

void client_on_stream_closed(void *   tctx, quic_conn_t *conn,
                             uint64_t stream_id)
{
    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "Connection[%"PRIu64"],Stream[%"PRIu64"] closed",
               quic_conn_index(conn), stream_id);
}

void client_on_conn_closed(void *tctx, quic_conn_t *conn)
{
    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "Connection[%"PRIu64"] closed", quic_conn_index(conn));
    // 停止并释放watcher
    for (int i = 0; i < plugin->ip_count; i++) {
        if (conn != plugin->conns[i]) {
            continue;
        }
        ev_io *watcher = plugin->ev_watchers[i];
        /* 你需要有某种方式来引用或存储每个创建的watcher */
        ;
        ev_io_stop(plugin->loop, watcher);
        watcher_data_t *watcher_data = (watcher_data_t *) watcher->data;

        // 如果有必要，释放watcher_data内部的资源

        free(watcher_data); // 释放watcher_data
        free(watcher);      // 释放watcher
        break;
    }
    // quic_conn_close(conn,true,0,NULL,0);
    if (quic_conn_is_idle_timeout(conn)) {
        plog_debug(plugin, "连接超时，关闭连接:%lu", quic_conn_index(conn));
        plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    } else if (quic_conn_is_closed(conn)) {
        plog_debug(plugin, "连接正常关闭:%lu", quic_conn_index(conn));
    }
}

void client_on_conn_created(void *tctx, quic_conn_t *conn)
{

    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "Connection[%"PRIu64"]created", quic_conn_index(conn));
    // quic_stream_wantwrite(conn, 0, true);

}

void client_on_conn_established(void *tctx, quic_conn_t *conn)
{
    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "Connection[%"PRIu64"] established",
               quic_conn_index(conn));
    // // id 0 is reserved for keepalive
    // quic_stream_new(conn, 0, 1, true);
    // // id 1 is reserved for data
    // quic_stream_new(conn, 1, 100, true);
    quic_stream_new(conn, 0, 10,true);
    quic_stream_wantwrite(conn, 0, true);

}


void client_on_stream_created(void *   tctx, quic_conn_t *conn,
                              uint64_t stream_id)
{
    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "Connection[%"PRIu64"],Stream[%"PRIu64"] created",
               quic_conn_index(conn), stream_id);
    // quic_stream_wantwrite(conn, stream_id,true);
}

void client_on_stream_readable(void *   tctx, quic_conn_t *conn,
                               uint64_t stream_id)
{

    neu_plugin_t *plugin = tctx;
    plog_debug(plugin, "Connection[%"PRIu64"],Stream[%"PRIu64"] readable",
               quic_conn_index(conn), stream_id);
    static uint8_t buf[READ_BUF_SIZE];
    bool fin = false;
    ssize_t r = quic_stream_read(conn, stream_id, buf, READ_BUF_SIZE, &fin);
    if (r < 0) {
        fprintf(stderr, "stream[%ld] read error\n", stream_id);
        return;
    }
    cJSON *json_data = cJSON_Parse(buf);
    if (json_data == NULL) {
        plog_debug(plugin, "json parse failed,close conn");
        const char *reason = "ok";
        quic_conn_close(conn, true, 0, (const uint8_t *) reason,
                        strlen(reason));
    }
    int status_code = cJSON_GetObjectItem(json_data, "status")->valueint;
    // switch status_code
    switch (status_code) {
    case HELLO:
        plog_debug(plugin, "server response hello");
        plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
        break;
    case SEND_DATA:
        break;
    default:
        cJSON_free(json_data);
        break;
    }
    if (fin) {
        plog_debug(plugin, "stream[%ld] read fin,close conn[%lu]", stream_id,
                   quic_conn_index(conn));
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
    plog_debug(plugin, "Connection[%"PRIu64"],Stream[%"PRIu64"] writable",
               quic_conn_index(conn), stream_id);
    // ip, 长度不超过16
    char *message = quic_conn_context(conn);

    if (plugin->common.link_state == NEU_NODE_LINK_STATE_DISCONNECTED) {
        unsigned char *compressed = NULL;
        char *data = NULL;
        size_t         compressed_size = 0;
        Message hello_msg = create_message(HelloRequest, message, HELLO, "[]");
        data      = serialize_message(&hello_msg);
        assert(
            compress_string(data, (unsigned char **) &compressed, &
                compressed_size) == Z_OK);
        plog_debug(plugin,"Connection[%"PRIu64"],Stream[%"PRIu64"] 压缩完成",quic_conn_index(conn), stream_id);
        if (quic_stream_write(conn, stream_id, compressed, compressed_size,
                              true)
            == compressed_size) {
            plog_debug(plugin,"Connection[%"PRIu64"],Stream[%"PRIu64"] 写入流成功",quic_conn_index(conn), stream_id);
            plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
        }
        if(compressed!=NULL) {
            free(compressed);
        }
        if(data!=NULL) {
            free(data);
        }
    } else {
        send_data(plugin, conn, stream_id);
    }
    // quic_stream_wantwrite(conn, stream_id, false);
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


int create_socket(const char *      host, const char *  port,
                  struct addrinfo **peer, neu_plugin_t *plugin)
{
    int                   succ_count = 0;
    const struct addrinfo hints      = {
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
            plugin->valid_sock_flag[i] = 0;
            continue;
        }
        // 让client->local_addr[i]的值等于local_addr
        plugin->local_addr[i]     = local_addr;
        plugin->local_addr_len[i] = sizeof(local_addr);
        fprintf(stdout, "%d:Successfully bound to %s:%d\n", i,
                inet_ntoa(plugin->local_addr[i].sin_addr),
                ntohs(plugin->local_addr[i].sin_port));
        plugin->valid_sock_flag[i] = 1;
    }
    return succ_count;
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
static void check_stop_cb(EV_P_ ev_timer *w, int revents) {
    neu_plugin_t *plugin = w->data;
    if (plugin->started == false) {
        plog_debug(plugin,"Stopping all event loop");
        ev_timer_stop(plugin->loop,&plugin->ev_timer);
        ev_timer_stop(plugin->loop, &plugin->keepalive_watcher);
        ev_timer_stop(plugin->loop, &plugin->check_stop_watcher);
        ev_break(EV_A_ EVBREAK_ALL); // 停止事件循环
    }
}
void send_keepalive(EV_P_ ev_timer *w, int revents)
{
    neu_plugin_t *plugin = w->data;
    plugin->started = true;
    plog_debug(plugin, "send keepalive");
    // Connect to server.
    plog_debug(plugin, "Connecting to server");
    for (int i = 0; i < plugin->ip_count; i++) {
        if (plugin->valid_sock_flag[i] == 0) {
            continue;
        }
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
        quic_conn_set_context(plugin->conns[i], plugin->ips[i]);
    }
    process_connections(plugin);
    plog_debug(plugin, "Start event loop");
    for (int i = 0; i < plugin->ip_count; i++) {
        if (plugin->valid_sock_flag[i] == 0) {
            continue;
        }
        watcher_data_t *watcher_data = malloc(sizeof(watcher_data_t));
        watcher_data->plugin         = plugin;
        watcher_data->sock_index     = i;
        ev_io *watcher               = malloc(sizeof(struct ev_io));
        ev_io_init(watcher, read_callback, plugin->sock[i], EV_READ);
        ev_io_start(plugin->loop, watcher);
        watcher->data          = watcher_data;
        plugin->ev_watchers[i] = watcher;
    }
}

const quic_transport_methods_t local_quic_transport_methods = {
    .on_conn_created = client_on_conn_created,
    .on_conn_established = client_on_conn_established,
    .on_conn_closed = client_on_conn_closed,
    .on_stream_created = client_on_stream_created,
    .on_stream_readable = client_on_stream_readable,
    .on_stream_writable = client_on_stream_writable,
    .on_stream_closed = client_on_stream_closed,
};

const quic_packet_send_methods_t local_quic_packet_send_methods = {
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


int start_quic_client(neu_plugin_t *plugin, float interval)
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
    int sock_count = create_socket(plugin->host, plugin->port, &plugin->peer,
                                   plugin);
    if (sock_count < plugin->ip_count) {
        for (int i = 0; i < plugin->ip_count; i++) {
            if (plugin->valid_sock_flag[i] == 0) {
                plog_error(plugin, "failed to create socket %d with ip:%s", i,
                           plugin->ips[i]);
            }
        }
    } else if (sock_count == plugin->ip_count) {
        plog_notice(plugin, "Successfully create all sockets");
    } else {
        plog_fatal(plugin, "Unknow error");
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
    // 初始化和启动保活定时器
//    ev_timer keepalive_watcher = malloc(sizeof(ev_timer));
    // 每 interval 秒发送一次保活包
    ev_timer_init(&plugin->keepalive_watcher, send_keepalive, 3.0, interval);
    plugin->keepalive_watcher.data = plugin;
    ev_timer_start(plugin->loop, &plugin->keepalive_watcher);

    // 初始化定时器，假设每1秒检查一次 plugin->started 变量, 如果为false则停止事件循环
    ev_timer_init(&plugin->check_stop_watcher, check_stop_cb, 1, 1);
    plugin->check_stop_watcher.data = plugin;
    ev_timer_start(plugin->loop, &plugin->check_stop_watcher);

    // 启动事件循环
    ev_loop(plugin->loop, 0);
    plog_debug(plugin,"Endpoint 事件循环结束,关闭插件");
EXIT:
    plog_debug(plugin,"开始释放资源");
    quic_endpoint_close(plugin->quic_endpoint,false);
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
    plog_debug(plugin,"资源释放完成");
    return 0;
}