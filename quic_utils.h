//
// Created by root on 3/30/24.
//

#ifndef NEURON_QUIC_UTILS_H
#define NEURON_QUIC_UTILS_H
#include "neuron.h"
typedef struct thread_args{
    neu_plugin_t *plugin;
    uint8_t interface_index;
    neu_reqresp_trans_data_t *incoming_data;
} thread_args_t;

#endif // NEURON_QUIC_UTILS_H
