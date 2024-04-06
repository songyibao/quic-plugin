#ifndef NEURON_PLUGIN_QUIC_H
#define NEURON_PLUGIN_QUIC_H

#include "client.h"
#include "ev.h"
#include <sqlite3.h>
#include "quic_utils.h"

#define MAX_IPS 10
#define MAX_IP_LEN 16 // Assuming IPv4 addresses are in the format "xxx.xxx.xxx.xxx\0"
struct neu_plugin {
    neu_plugin_common_t  common;
    char                *host;
    char                *port;
    bool                 started;
    unsigned char timer;

    sqlite3 *db;

    char *table_name;
    uint16_t msg_buffer_size;

    char *ips[MAX_IPS];
    uint8_t ip_count;
    pthread_t     thread_ids[MAX_IPS];
    pthread_t thread_client_start_id;
    thread_args_t thread_client_start_args;
    thread_args_t thread_args[MAX_IPS];


    // quic client
    quic_endpoint_t* quic_endpoint; //
    quic_config_t* config; //
    struct addrinfo* peer; //
    ev_timer ev_timer;
    ev_io *ev_watchers[MAX_IPS];
    SSL_CTX* ssl_ctx; //
    struct ev_loop* loop; //
    quic_conn_t* conns[MAX_IPS];
    int sock[MAX_IPS];
    struct sockaddr_in local_addr[MAX_IPS];
    socklen_t local_addr_len[MAX_IPS];
};
static neu_plugin_t *driver_open(void);

static int driver_close(neu_plugin_t *plugin);
static int driver_init(neu_plugin_t *plugin, bool load);
static int driver_uninit(neu_plugin_t *plugin);
static int driver_start(neu_plugin_t *plugin);
static int driver_stop(neu_plugin_t *plugin);
static int driver_config(neu_plugin_t *plugin, const char *config);
static int driver_request(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                          void *data);

static int driver_validate_tag(neu_plugin_t *plugin, neu_datatag_t *tag);
static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group);
static int driver_write(neu_plugin_t *plugin, void *req, neu_datatag_t *tag,
                        neu_value_u value);

#endif