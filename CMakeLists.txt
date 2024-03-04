

set(LIBRARY_OUTPUT_PATH "./")
#file(COPY ${CMAKE_SOURCE_DIR}/plugins/quic/quic.json DESTINATION ${CMAKE_BINARY_DIR}/plugins/schema/)
set(src
        quic.c
        client.c
        json_rw.c
        quic_handle.c)

add_library(plugin-quic SHARED ${src})

target_include_directories(plugin-quic PRIVATE
#        ${CMAKE_SOURCE_DIR}/include/neuron
        /home/songyibao/Downloads/neuron-main/include/neuron
#        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tquic/include
        /home/songyibao/Downloads/neuron-main/plugins/quic/deps/tquic/include
)

#target_link_libraries(plugin-quic PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/deps/tquic/target/release/libtquic.a)
target_link_libraries(plugin-quic PRIVATE /home/songyibao/Downloads/neuron-main/plugins/quic/deps/tquic/target/release/libtquic.a)

target_link_libraries(plugin-quic PRIVATE  ev)
target_link_libraries(plugin-quic PRIVATE /usr/local/lib/neuron)