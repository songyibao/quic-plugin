

project(plugin-quic)


file(COPY ${CMAKE_SOURCE_DIR}/plugins/quic/quic.json DESTINATION ${CMAKE_BINARY_DIR}/plugins/schema/)

add_library(${PROJECT_NAME} SHARED
        quic.c
        quic_config.c
        quic_handle.c
        client.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include/neuron
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tquic/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE neuron-base)
target_link_libraries(${PROJECT_NAME} PRIVATE ev)
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/deps/tquic/target/release/libtquic.a)
#target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})
