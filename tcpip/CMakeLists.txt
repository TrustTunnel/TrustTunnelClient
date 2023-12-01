cmake_minimum_required(VERSION 3.24)
project(tcpip C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

find_package(Threads REQUIRED)
if(CMAKE_USE_PTHREADS_INIT)
    add_compile_options("-pthread")
endif()

set(VPN_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(THIRD_PARTY_DIR ${VPN_LIB_DIR}/third-party)
set(TCPIP_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

set(LWIP_DIR ${THIRD_PARTY_DIR}/lwip/lwip)
set(LWIP_INCLUDE_DIRS ${LWIP_DIR}/src/include)
include(${LWIP_DIR}/src/Filelists.cmake)
set_property(SOURCE ${LWIP_DIR}/src/core/timeouts.c APPEND PROPERTY COMPILE_DEFINITIONS tcp_timer_needed=tcp_timer_needed_stub)

set(SOURCE_FILES
        ${TCPIP_SOURCE_DIR}/tcpip_api.cpp
        ${TCPIP_SOURCE_DIR}/libevent_lwip.h
        ${TCPIP_SOURCE_DIR}/libevent_lwip.cpp
        ${TCPIP_SOURCE_DIR}/tcp_raw.h
        ${TCPIP_SOURCE_DIR}/tcp_raw.cpp
        ${TCPIP_SOURCE_DIR}/tcp_connection.h
        ${TCPIP_SOURCE_DIR}/tcp_conn_manager.h
        ${TCPIP_SOURCE_DIR}/tcp_conn_manager.cpp
        ${TCPIP_SOURCE_DIR}/udp_raw.h
        ${TCPIP_SOURCE_DIR}/udp_raw.cpp
        ${TCPIP_SOURCE_DIR}/udp_connection.h
        ${TCPIP_SOURCE_DIR}/udp_conn_manager.h
        ${TCPIP_SOURCE_DIR}/udp_conn_manager.cpp
        ${TCPIP_SOURCE_DIR}/tcpip_common.h
        ${TCPIP_SOURCE_DIR}/tcpip_common.cpp
        ${TCPIP_SOURCE_DIR}/ip_hooks.h
        ${TCPIP_SOURCE_DIR}/ip_hooks.cpp
        ${TCPIP_SOURCE_DIR}/tcpip_util.cpp
        ${TCPIP_SOURCE_DIR}/icmp_request_manager.h
        ${TCPIP_SOURCE_DIR}/icmp_request_manager.cpp
        ${TCPIP_SOURCE_DIR}/icmp_request.h
        ${TCPIP_SOURCE_DIR}/icmp_request.cpp
        ${TCPIP_SOURCE_DIR}/vpn_packet_pool.cpp
        ${TCPIP_SOURCE_DIR}/vpn_packet_pool.h
    )

if(NOT TARGET vpnlibs_common)
    add_subdirectory(${VPN_LIB_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET vpnlibs_common)

if(NOT TARGET vpnlibs_net)
    add_subdirectory(${VPN_LIB_DIR}/net ${CMAKE_BINARY_DIR}/net)
endif(NOT TARGET vpnlibs_net)

add_library(vpnlibs_tcpip STATIC EXCLUDE_FROM_ALL
    ${lwipcore_SRCS}
    ${lwipcore4_SRCS}
    ${lwipcore6_SRCS}
    ${SOURCE_FILES})
set_target_properties(vpnlibs_tcpip PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(NOT MSVC)
    target_compile_options(vpnlibs_tcpip PRIVATE -W -Wall -Wextra -Werror)
    target_compile_options(vpnlibs_tcpip PRIVATE
            -Wno-unknown-warning-option -Wno-macro-redefined -Wno-unused-parameter
            -Wno-missing-field-initializers -Wno-c99-designator)
endif()
target_include_directories(vpnlibs_tcpip PUBLIC include)
target_include_directories(vpnlibs_tcpip PRIVATE ${LWIP_INCLUDE_DIRS})
target_include_directories(vpnlibs_tcpip PRIVATE src)
target_include_directories(vpnlibs_tcpip PRIVATE ${THIRD_PARTY_DIR}/pcap_savefile/include)

find_package(klib REQUIRED)
find_package(libevent REQUIRED)

target_link_libraries(vpnlibs_tcpip vpnlibs_common vpnlibs_net)
target_link_libraries(vpnlibs_tcpip klib::klib libevent::libevent)


enable_testing()
include(${VPN_LIB_DIR}/cmake/add_unit_test.cmake)
link_libraries(vpnlibs_tcpip)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
set(TEST_EXTRA_INCLUDES ${LWIP_INCLUDE_DIRS} src)

include_directories(${LWIP_INCLUDE_DIRS} src)


add_unit_test(test_util "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" FALSE FALSE)
add_unit_test(test_vpn_packet_pool "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
