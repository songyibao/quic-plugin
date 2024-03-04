
#ifndef NEURON_PLUGIN_QUIC_CLIENT_H
#define NEURON_PLUGIN_QUIC_CLIENT_H
#define UNUSED(x) (void) x
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "openssl/ssl.h"
#include "tquic.h"

#define READ_BUF_SIZE 4096
#define MAX_DATAGRAM_SIZE 1200

// A simple client that supports HTTP/0.9 over QUIC
typedef struct simple_client {
    struct quic_endpoint_t *quic_endpoint;
    quic_config_t          *config;
    struct addrinfo        *peer;
    ev_timer                timer;
    int                     sock;
    struct sockaddr_storage local_addr;
    socklen_t               local_addr_len;
    SSL_CTX                *ssl_ctx;
    struct quic_conn_t     *conn;
    struct ev_loop         *loop;
} simple_client_t;

void client_on_conn_created(void *tctx, struct quic_conn_t *conn);

void client_on_conn_closed(void *tctx, struct quic_conn_t *conn);

void client_on_stream_created(void *tctx, struct quic_conn_t *conn,
                              uint64_t stream_id);

void client_on_stream_readable(void *tctx, struct quic_conn_t *conn,
                               uint64_t stream_id);

void client_on_stream_closed(void *tctx, struct quic_conn_t *conn,
                             uint64_t stream_id);

int client_on_packets_send(void *psctx, struct quic_packet_out_spec_t *pkts,
                           unsigned int count);

extern char s_alpn[0x100];

int add_alpn(const char *alpn);

int client_load_ssl_ctx(struct simple_client *client);

extern const struct quic_transport_methods_t quic_transport_methods;

extern const struct quic_packet_send_methods_t quic_packet_send_methods;

void process_connections(struct simple_client *client);

void read_callback(EV_P_ ev_io *w, int revents);

void timeout_callback(EV_P_ ev_timer *w, int revents);

void debug_log(const unsigned char *line, void *argp);

int create_socket(const char *host, const char *port, struct addrinfo **peer,
                  struct simple_client *client);

#endif