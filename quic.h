#ifndef NEURON_PLUGIN_QUIC_H
#define NEURON_PLUGIN_QUIC_H

#include "client.h"
#include "ev.h"
#include <sqlite3.h>

struct neu_plugin {
    neu_plugin_common_t  common;
    char                *host;
    char                *port;
    bool                 started;
    unsigned char timer;
    sqlite3 *db;
    char *table_name;
    uint16_t msg_buffer_size;
};
extern neu_plugin_t *local_plugin;
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