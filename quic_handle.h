#ifndef NEURON_PLUGIN_QUIC_HANDLE_H
#define NEURON_PLUGIN_QUIC_HANDLE_H



#include "neuron.h"
#include "plugin.h"
//void handle_write_req(neu_mqtt_qos_e qos, const char *topic,
//                     const uint8_t *payload, uint32_t len, void *data);
//
//int handle_write_response(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt_json,
//                         neu_resp_error_t *data);
//
//void handle_read_req(neu_mqtt_qos_e qos, const char *topic,
//                    const uint8_t *payload, uint32_t len, void *data);

int handle_read_response(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt_json,
                        neu_resp_read_group_t *data);

int handle_trans_data(neu_plugin_t *            plugin,
                     neu_reqresp_trans_data_t *trans_data);

int handle_subscribe_group(neu_plugin_t *plugin, neu_req_subscribe_t *sub_info);
int handle_update_subscribe(neu_plugin_t *       plugin,
                           neu_req_subscribe_t *sub_info);
int handle_unsubscribe_group(neu_plugin_t *         plugin,
                            neu_req_unsubscribe_t *unsub_info);

int handle_update_group(neu_plugin_t *plugin, neu_req_update_group_t *req);

int handle_update_driver(neu_plugin_t *plugin, neu_req_update_node_t *req);
int handle_del_driver(neu_plugin_t *plugin, neu_reqresp_node_deleted_t *req);

#endif