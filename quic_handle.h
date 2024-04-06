#ifndef NEURON_PLUGIN_QUIC_HANDLE_H
#define NEURON_PLUGIN_QUIC_HANDLE_H



int parse_send_data(neu_plugin_t *plugin, quic_conn_t *conn,
                    neu_reqresp_trans_data_t *trans_data);

int handle_read_response(neu_plugin_t *plugin, neu_json_mqtt_t *mqtt_json,
                        neu_resp_read_group_t *data);
int handle_insert_data(neu_plugin_t *            plugin,
                      neu_reqresp_trans_data_t *trans_data);
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