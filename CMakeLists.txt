set(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}/plugins")

set(QUIC_SRC client.h ${CMAKE_CURRENT_SOURCE_DIR}/deps/tquic/include/tquic.h)

set(CMAKE_BUILD_RPATH ./)
file(COPY ${CMAKE_SOURCE_DIR}/plugins/quic/quic.json DESTINATION ${CMAKE_BINARY_DIR}/plugins/schema/)
# modbus quic plugin
set(QUIC_PLUGIN plugin-quic)
set(QUIC_PLUGIN_SOURCES  quic.c
        ${QUIC_SRC})
add_library(${QUIC_PLUGIN} SHARED)
target_include_directories(${QUIC_PLUGIN} PRIVATE ${CMAKE_SOURCE_DIR}/include/neuron)


# Add the directory containing the header files to the include path
target_include_directories(${QUIC_PLUGIN} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/deps/tquic/include)
target_sources(${QUIC_PLUGIN} PRIVATE ${QUIC_PLUGIN_SOURCES})



# 将 libev 库链接到您的目标可执行文件
#add_executable(your_executable your_source_files.c)
link_directories("/usr/local/lib")


target_link_libraries(${QUIC_PLUGIN} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/deps/tquic/target/release/libtquic.a)
target_link_libraries(${QUIC_PLUGIN} PRIVATE  ev)
target_link_libraries(${QUIC_PLUGIN} PRIVATE neuron-base)



