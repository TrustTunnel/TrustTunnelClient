cmake_minimum_required(VERSION 3.24)
project(net C CXX)


set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

set(VPN_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(THIRD_PARTY_DIR ${VPN_LIB_DIR}/third-party)
set(NET_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

set(SOURCE_FILES
        ${NET_SOURCE_DIR}/tcp_socket.cpp
        ${NET_SOURCE_DIR}/udp_socket.cpp
        ${NET_SOURCE_DIR}/tls.cpp
        ${NET_SOURCE_DIR}/http_header.cpp
        ${NET_SOURCE_DIR}/http_session.cpp
        ${NET_SOURCE_DIR}/http_stream.cpp
        ${NET_SOURCE_DIR}/http1.cpp
        ${NET_SOURCE_DIR}/http2.cpp
        ${NET_SOURCE_DIR}/util.cpp
        ${NET_SOURCE_DIR}/socks5_listener.cpp
        ${NET_SOURCE_DIR}/dns_manager.cpp
        ${NET_SOURCE_DIR}/socket_manager.cpp
        ${NET_SOURCE_DIR}/network_manager.cpp
        ${NET_SOURCE_DIR}/ping.cpp
        ${NET_SOURCE_DIR}/locations_pinger.cpp
        ${NET_SOURCE_DIR}/locations_pinger_runner.cpp
        ${NET_SOURCE_DIR}/dns_utils.cpp
        ${NET_SOURCE_DIR}/quic_utils.cpp
        ${NET_SOURCE_DIR}/os_tunnel.cpp
        ${NET_SOURCE_DIR}/tls13_utils.cpp
    )

string(TOLOWER "${CMAKE_OSX_SYSROOT}" OSX_SYSROOT_LC)
if(APPLE AND OSX_SYSROOT_LC MATCHES "/macosx([0-9]+\.)+sdk$")
    list(APPEND SOURCE_FILES ${NET_SOURCE_DIR}/os_tunnel_mac.cpp)
    list(APPEND SOURCE_FILES ${NET_SOURCE_DIR}/mac_dns_settings_manager.mm)
elseif(WIN32)
    list(APPEND SOURCE_FILES ${NET_SOURCE_DIR}/os_tunnel_win.cpp)
    list(APPEND SOURCE_FILES ${NET_SOURCE_DIR}/wfp_firewall.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
    list(APPEND SOURCE_FILES ${NET_SOURCE_DIR}/os_tunnel_linux.cpp)
endif()

if(NOT TARGET vpnlibs_common)
    add_subdirectory(${VPN_LIB_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET vpnlibs_common)

add_library(vpnlibs_net STATIC EXCLUDE_FROM_ALL ${SOURCE_FILES})
set_target_properties(vpnlibs_net PROPERTIES POSITION_INDEPENDENT_CODE ON)
if (NOT MSVC)
    target_compile_options(vpnlibs_net PRIVATE -W -Wall -Wextra -Werror)
    target_compile_options(vpnlibs_net PRIVATE
            -Wno-unknown-warning-option -Wno-macro-redefined -Wno-unused-parameter
            -Wno-missing-field-initializers -Wno-c99-designator)
    if(APPLE AND OSX_SYSROOT_LC MATCHES "/macosx([0-9]+\.)+sdk$")
        target_compile_options(vpnlibs_net PRIVATE -fobjc-arc)
        target_link_libraries(vpnlibs_net "-framework Foundation" "-framework SystemConfiguration")
    endif()
else()
    target_include_directories(vpnlibs_net PRIVATE ${THIRD_PARTY_DIR}/wintun/include)
endif()
target_include_directories(vpnlibs_net PUBLIC include)

find_package(ZLIB REQUIRED)
find_package(brotli REQUIRED)
find_package(http_parser REQUIRED)
find_package(ldns REQUIRED)
find_package(nghttp2 REQUIRED)
find_package(klib REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(libevent REQUIRED)
find_package(quiche REQUIRED)
find_package(magic_enum REQUIRED)

target_link_libraries(vpnlibs_net vpnlibs_common)
target_link_libraries(vpnlibs_net ZLIB::ZLIB brotli::brotli http_parser::http_parser)
target_link_libraries(vpnlibs_net ldns::ldns nghttp2::nghttp2 klib::klib openssl::openssl)
target_link_libraries(vpnlibs_net libevent::libevent quiche::quiche magic_enum::magic_enum)
if (WIN32)
    target_link_libraries(vpnlibs_net BCrypt) # Quiche requirement
    target_link_libraries(vpnlibs_net Fwpuclnt) # WFP firewall
    target_link_libraries(vpnlibs_net wsock32 ws2_32 ntdll iphlpapi)
else()
    target_link_libraries(vpnlibs_net resolv)
    if (APPLE)
        target_link_libraries(vpnlibs_net "-framework CoreFoundation" "-framework Security")
    endif ()
endif()

enable_testing()

find_package(nlohmann_json REQUIRED)
include(${VPN_LIB_DIR}/cmake/add_unit_test.cmake)
link_libraries(vpnlibs_net nlohmann_json::nlohmann_json)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
set(TEST_EXTRA_INCLUDES ${NET_SOURCE_DIR})

add_unit_test(test_http_headers "${TEST_DIR}" "" FALSE FALSE)
add_unit_test(test_tls_parse "${TEST_DIR}" "" FALSE FALSE)
add_unit_test(test_ping "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_quic_parse "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_locations_pinger "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_locations_pinger_runner "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_dns_utils "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_tls_serialize "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_net_utils "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
