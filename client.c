// #include "client.h"
//
// int main(int argc, char *argv[]) {
//     if (argc < 3) {
//         fprintf(stderr, "%s <dest_addr> <dest_port>\n", argv[0]);
//         return -1;
//     }
//
//     // Set logger.
//     quic_set_logger(debug_log, NULL, QUIC_LOG_LEVEL_TRACE);
//
//     // Create client.
//     struct simple_client client;
//     client.quic_endpoint = NULL;
//     client.ssl_ctx = NULL;
//     client.conn = NULL;
//     client.loop = NULL;
//     quic_config_t *config = NULL;
//     int ret = 0;
//
//     // Create socket.
//     const char *host = argv[1];
//     const char *port = argv[2];
//     struct addrinfo *peer = NULL;
//     if (create_socket(host, port, &peer, &client) != 0) {
//         ret = -1;
//         goto EXIT;
//     }
//
//     // Create quic config.
//     config = quic_config_new();
//     if (config == NULL) {
//         fprintf(stderr, "failed to create config\n");
//         ret = -1;
//         goto EXIT;
//     }
//     quic_config_set_max_idle_timeout(config, 5000);
//     quic_config_set_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
//
//     // Create and set tls config.
//     if (client_load_ssl_ctx(&client) != 0) {
//         ret = -1;
//         goto EXIT;
//     }
//     quic_config_set_tls_config(config, client.ssl_ctx);
//
//     // Create quic endpoint
//     client.quic_endpoint =
//         quic_endpoint_new(config, false, &quic_transport_methods, &client,
//                           &quic_packet_send_methods, &client);
//     if (client.quic_endpoint == NULL) {
//         fprintf(stderr, "failed to create quic endpoint\n");
//         ret = -1;
//         goto EXIT;
//     }
//
//     // Init event loop.
//     client.loop = ev_default_loop(0);
//     ev_init(&client.timer, timeout_callback);
//     client.timer.data = &client;
//
//     // Connect to server.
//     ret = quic_endpoint_connect(
//         client.quic_endpoint, (struct sockaddr *)&client.local_addr,
//         client.local_addr_len, peer->ai_addr, peer->ai_addrlen,
//         NULL /* client_name*/, NULL /* session */, 0 /* session_len */,
//         NULL /* token */, 0 /* token_len */, NULL /*index*/);
//     if (ret < 0) {
//         fprintf(stderr, "failed to connect to client: %d\n", ret);
//         ret = -1;
//         goto EXIT;
//     }
//     process_connections(&client);
//
//     // Start event loop.
//     ev_io watcher;
//     ev_io_init(&watcher, read_callback, client.sock, EV_READ);
//     ev_io_start(client.loop, &watcher);
//     watcher.data = &client;
//     ev_loop(client.loop, 0);
//
// EXIT:
//     if (peer != NULL) {
//         freeaddrinfo(peer);
//     }
//     if (client.ssl_ctx != NULL) {
//         SSL_CTX_free(client.ssl_ctx);
//     }
//     if (client.sock > 0) {
//         close(client.sock);
//     }
//     if (client.quic_endpoint != NULL) {
//         quic_endpoint_free(client.quic_endpoint);
//     }
//     if (client.loop != NULL) {
//         ev_loop_destroy(client.loop);
//     }
//     if (config != NULL) {
//         quic_config_free(config);
//     }
//
//     return ret;
// }
