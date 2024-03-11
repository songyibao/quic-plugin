
#include "client.h"
#include "quic.h"



void client_on_stream_writable(void *tctx, struct quic_conn_t *conn,uint64_t stream_id)
{
}
void client_on_stream_closed(void *tctx, struct quic_conn_t *conn,uint64_t stream_id)
{

}
void client_on_conn_closed(void *tctx, struct quic_conn_t *conn)
{
    struct simple_client *client = tctx;
    ev_break(client->loop, EVBREAK_ALL);
}
void client_on_conn_established(void *tctx, struct quic_conn_t *conn)
{
    const char *data = "GET /\r\n";
    quic_stream_write(conn, 0, (uint8_t *)data, strlen(data), true);
}
const struct quic_transport_methods_t quic_transport_methods = {
    .on_conn_created     = client_on_conn_created,
    .on_conn_established = client_on_conn_established,
    .on_conn_closed      = client_on_conn_closed,
    .on_stream_created   = client_on_stream_created,
    .on_stream_readable  = client_on_stream_readable,
    .on_stream_writable  = client_on_stream_writable,
    .on_stream_closed    = client_on_stream_closed,
};

const struct quic_packet_send_methods_t quic_packet_send_methods = {
    .on_packets_send = client_on_packets_send,
};
void client_on_conn_created(void *tctx, struct quic_conn_t *conn) {
    struct simple_client *client = tctx;
    client->conn = conn;
}
// Function to create and send JSON data to the server


// Modify client_on_conn_established function to call send_json_data

void client_on_stream_created(void *tctx, struct quic_conn_t *conn,
                              uint64_t stream_id) {}

void client_on_stream_readable(void *tctx, struct quic_conn_t *conn,
                               uint64_t stream_id) {
    static uint8_t buf[READ_BUF_SIZE];
    bool fin = false;
    ssize_t r = quic_stream_read(conn, stream_id, buf, READ_BUF_SIZE, &fin);
    if (r < 0) {
        fprintf(stderr, "stream[%ld] read error\n", stream_id);
        return;
    }
    local_plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
    nlog_notice("rec msg from server:%.*s", (int)r, buf);
    if (fin) {
        nlog_notice("server says fin:true");
        const char *reason = "ok";
        quic_conn_close(conn, true, 0, (const uint8_t *)reason, strlen(reason));
        //by default, node is connected after connection try

    }

}




int client_on_packets_send(void *psctx, struct quic_packet_out_spec_t *pkts,
                           unsigned int count) {
    struct simple_client *client = psctx;

    unsigned int sent_count = 0;
    // int sent_count = 0;
    int i, j = 0;
    for (i = 0; i < (int)count; i++) {
        struct quic_packet_out_spec_t *pkt = pkts + i;
        for (j = 0; j < (int)(*pkt).iovlen; j++) {
            const struct iovec *iov = pkt->iov + j;
            ssize_t sent =
                sendto(client->sock, iov->iov_base, iov->iov_len, 0,
                       (struct sockaddr *)pkt->dst_addr, pkt->dst_addr_len);

            if (sent != iov->iov_len) {
                if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                    fprintf(stderr, "send would block, already sent: %d\n",
                            sent_count);
                    return sent_count;
                }
                return -1;
            }
            sent_count++;
        }
    }

    return sent_count;
}

char s_alpn[0x100];

int add_alpn(const char *alpn) {
    size_t alpn_len, all_len;

    alpn_len = strlen(alpn);
    if (alpn_len > 255) return -1;

    all_len = strlen(s_alpn);
    if (all_len + 1 + alpn_len + 1 > sizeof(s_alpn)) return -1;

    s_alpn[all_len] = alpn_len;
    memcpy(&s_alpn[all_len + 1], alpn, alpn_len);
    s_alpn[all_len + 1 + alpn_len] = '\0';
    return 0;
}

int client_load_ssl_ctx(struct simple_client *client) {
    add_alpn("http/0.9");
    client->ssl_ctx = SSL_CTX_new(TLS_method());
    if (SSL_CTX_set_default_verify_paths(client->ssl_ctx) != 1) {
        fprintf(stderr, "set default verify path failed\n");
        return -1;
    }
    if (SSL_CTX_set_alpn_protos(client->ssl_ctx, (const unsigned char *)s_alpn,
                                strlen(s_alpn)) != 0) {
        fprintf(stderr, "set alpn failed\n");
        return -1;
    }

    return 0;
}



void process_connections(struct simple_client *client) {
    quic_endpoint_process_connections(client->quic_endpoint);
    double timeout = quic_endpoint_timeout(client->quic_endpoint) / 1e3f;
    if (timeout < 0.0001) {
        timeout = 0.0001;
    }
    client->timer.repeat = timeout;
    ev_timer_again(client->loop, &client->timer);
}

void read_callback(EV_P_ ev_io *w, int revents) {
    struct simple_client *client = w->data;
    static uint8_t buf[READ_BUF_SIZE];

    while (true) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(client->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                break;
            }

            fprintf(stderr, "failed to read\n");
            return;
        }

        quic_packet_info_t quic_packet_info = {
            .src = (struct sockaddr *)&peer_addr,
            .src_len = peer_addr_len,
            .dst = (struct sockaddr *)&client->local_addr,
            .dst_len = client->local_addr_len,
        };

        int r = quic_endpoint_recv(client->quic_endpoint, buf, read,
                                   &quic_packet_info);
        if (r != 0) {
            fprintf(stderr, "recv failed %d\n", r);
            continue;
        }
    }

    process_connections(client);
}

void example_timeout_callback(EV_P_ ev_timer *w, int revents) {
    struct simple_client *client = w->data;
    quic_endpoint_on_timeout(client->quic_endpoint);
    process_connections(client);
}



void debug_log(const unsigned char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

int create_socket(const char *host, const char *port,
                         struct addrinfo **peer, struct simple_client *client) {
    const struct addrinfo hints = {.ai_family = PF_UNSPEC,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};
    if (getaddrinfo(host, port, &hints, peer) != 0) {
        fprintf(stderr, "failed to resolve host\n");
        return -1;
    }

    int sock = socket((*peer)->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "failed to create socket\n");
        return -1;
    }
    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        fprintf(stderr, "failed to make socket non-blocking\n");
        return -1;
    }

    client->local_addr_len = sizeof(client->local_addr);
    if (getsockname(sock, (struct sockaddr *)&client->local_addr,
                    &client->local_addr_len) != 0) {
        fprintf(stderr, "failed to get local address of socket\n");
        return -1;
    };
    client->sock = sock;

    return 0;
}

int new_client(neu_plugin_t *plugin, TimeoutCallback timeout_callback, OnConnEstablishedCallback on_conn_established_callback)
{
    const struct quic_transport_methods_t local_quic_transport_methods = {
        .on_conn_created     = client_on_conn_created,
        .on_conn_established = on_conn_established_callback,
        .on_conn_closed      = client_on_conn_closed,
        .on_stream_created   = client_on_stream_created,
        .on_stream_readable  = client_on_stream_readable,
        .on_stream_writable  = client_on_stream_writable,
        .on_stream_closed    = client_on_stream_closed,
    };
    // Set logger.
    quic_set_logger(debug_log, NULL, QUIC_LOG_LEVEL_OFF);

    // Create client.
    struct simple_client client;
    client.quic_endpoint  = NULL;
    client.ssl_ctx        = NULL;
    client.conn           = NULL;
    client.loop           = NULL;
    quic_config_t *config = NULL;
    int            ret    = 0;

    // Create socket.
    const char      *host = plugin->host;
    const char      *port = plugin->port;
    struct addrinfo *peer = NULL;
    if (create_socket(host, port, &peer, &client) != 0) {
        ret = -1;
        goto EXIT;
    }

    // Create quic config.
    config = quic_config_new();
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        ret = -1;
        goto EXIT;
    }
    quic_config_set_max_idle_timeout(config, 5000);
    quic_config_set_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);

    // Create and set tls config.
    if (client_load_ssl_ctx(&client) != 0) {
        ret = -1;
        goto EXIT;
    }
    quic_config_set_tls_config(config, client.ssl_ctx);

    // Create quic endpoint
    client.quic_endpoint =
        quic_endpoint_new(config, false, &local_quic_transport_methods, &client,
                          &quic_packet_send_methods, &client);
    if (client.quic_endpoint == NULL) {
        fprintf(stderr, "failed to create quic endpoint\n");
        ret = -1;
        goto EXIT;
    }

    // Init event loop.
    client.loop = ev_default_loop(0);
    ev_init(&client.timer, timeout_callback);
    client.timer.data = &client;

    // Connect to server.
    ret = quic_endpoint_connect(
        client.quic_endpoint, (struct sockaddr *) &client.local_addr,
        client.local_addr_len, peer->ai_addr, peer->ai_addrlen,
        NULL /* client_name*/, NULL /* session */, 0 /* session_len */,
        NULL /* token */, 0 /* token_len */, NULL /*index*/);

    if (ret < 0) {
        fprintf(stderr, "failed to connect to client: %d\n", ret);
        ret = -1;
        goto EXIT;
    }
    process_connections(&client);

    // Start event loop.
    ev_io watcher;
    ev_io_init(&watcher, read_callback, client.sock, EV_READ);
    ev_io_start(client.loop, &watcher);
    watcher.data = &client;
    ev_loop(client.loop, 0);
    goto  EXIT;

EXIT:
    if (peer != NULL) {
        freeaddrinfo(peer);
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
    if (config != NULL) {
        quic_config_free(config);
    }
//    free(&client);
    return ret;
}