cmake_minimum_required(VERSION 3.1)
project(net C CXX)


set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)


set(VPN_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(THIRD_PARTY_DIR ${VPN_LIB_DIR}/third-party)
set(NET_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)


include(../cmake/conan_bootstrap.cmake)
conan_bootstrap(SRCROOT ".." CONANFILE "../conanfile.py" SCOPE_NAME agvpn)


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
    )


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
endif()
target_include_directories(vpnlibs_net PUBLIC include)

target_link_libraries(vpnlibs_net vpnlibs_common)
target_link_libraries(vpnlibs_net CONAN_PKG::zlib CONAN_PKG::brotli CONAN_PKG::http_parser)
target_link_libraries(vpnlibs_net CONAN_PKG::ldns CONAN_PKG::nghttp2 CONAN_PKG::klib CONAN_PKG::openssl)
target_link_libraries(vpnlibs_net CONAN_PKG::libevent CONAN_PKG::quiche)
if (WIN32)
    target_link_libraries(vpnlibs_net BCrypt) # Quiche requirement
endif()

if (APPLE)
    target_link_libraries(vpnlibs_net "-framework CoreFoundation" "-framework Security")
endif ()
if (MSVC)
    target_link_libraries(vpnlibs_net "Iphlpapi.lib")
endif ()

enable_testing()

include(${VPN_LIB_DIR}/cmake/add_unit_test.cmake)
link_libraries(vpnlibs_net CONAN_PKG::nlohmann_json)
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
