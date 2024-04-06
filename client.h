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
#include "neuron.h"
#include "plugin.h"
#include "quic.h"

#define READ_BUF_SIZE 4096
#define MAX_DATAGRAM_SIZE 1200
#define MAX_IPS 10

// A simple client that supports HTTP/0.9 over QUIC
// typedef struct simple_client
// {
//     struct quic_endpoint_t* quic_endpoint; //
//     quic_config_t* config; //
//     struct addrinfo* peer; //
//     ev_timer timer;
//     // int                     sock; //
//     // struct sockaddr_storage local_addr;
//     // socklen_t               local_addr_len;
//     SSL_CTX* ssl_ctx; //
//     quic_conn_t* conn;
//     struct ev_loop* loop; //
//     neu_plugin_t* plugin; // 传入回调函数的上下文信息
//
//     char* ips[MAX_IPS];
//     uint8_t ip_count;
//     int sock[MAX_IPS];
//     struct sockaddr_in local_addr[MAX_IPS];
//     socklen_t local_addr_len[MAX_IPS];
// } simple_client_t;

typedef void (*TimeoutCallback)(EV_P_ ev_timer* w, int revents);
typedef void (*OnConnEstablishedCallback)(void* tctx, quic_conn_t* conn);
int compress_string(const char* str, unsigned char** compressed, size_t* compressed_size);
// void client_on_stream_writable(void* tctx, quic_conn_t* conn, uint64_t stream_id);
// void client_on_stream_closed(void* tctx, quic_conn_t* conn, uint64_t stream_id);
// void client_on_conn_closed(void* tctx, quic_conn_t* conn);
// void client_on_conn_established(void* tctx, quic_conn_t* conn);
// void client_on_conn_created(void* tctx, quic_conn_t* conn);
// void client_on_stream_created(void* tctx, quic_conn_t* conn, uint64_t stream_id);
// void client_on_stream_readable(void* tctx, quic_conn_t* conn, uint64_t stream_id);
// int client_on_packets_send(void* psctx, quic_packet_out_spec_t* pkts, unsigned int count);


int start_quic_client(neu_plugin_t *plugin);

#endif
