cmake_minimum_required(VERSION 3.24)
project(core C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

set(VPN_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(THIRD_PARTY_DIR ${VPN_LIB_DIR}/third-party)
set(VPNCORE_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

set(SOURCE_FILES
        ${VPNCORE_SRC_DIR}/dns_proxy_accessor.cpp
        ${VPNCORE_SRC_DIR}/vpn_client.cpp
        ${VPNCORE_SRC_DIR}/vpn_manager.cpp
        ${VPNCORE_SRC_DIR}/vpn_fsm.cpp
        ${VPNCORE_SRC_DIR}/tunnel.cpp
        ${VPNCORE_SRC_DIR}/socks_listener.cpp
        ${VPNCORE_SRC_DIR}/tun_device_listener.cpp
        ${VPNCORE_SRC_DIR}/http2_upstream.cpp
        ${VPNCORE_SRC_DIR}/http3_upstream.cpp
        ${VPNCORE_SRC_DIR}/upstream_multiplexer.cpp
        ${VPNCORE_SRC_DIR}/http_udp_multiplexer.cpp
        ${VPNCORE_SRC_DIR}/http_icmp_multiplexer.cpp
        ${VPNCORE_SRC_DIR}/direct_upstream.cpp
        ${VPNCORE_SRC_DIR}/fake_upstream.cpp
        ${VPNCORE_SRC_DIR}/utils.cpp
        ${VPNCORE_SRC_DIR}/domain_filter.cpp
        ${VPNCORE_SRC_DIR}/domain_lookuper.cpp
        ${VPNCORE_SRC_DIR}/memory_buffer.cpp
        ${VPNCORE_SRC_DIR}/memfile_buffer.cpp
        ${VPNCORE_SRC_DIR}/single_upstream_connector.cpp
        ${VPNCORE_SRC_DIR}/fallbackable_upstream_connector.cpp
        ${VPNCORE_SRC_DIR}/icmp_manager.cpp
        ${VPNCORE_SRC_DIR}/plain_dns_message_handler.cpp
        ${VPNCORE_SRC_DIR}/plain_dns_manager.cpp
        ${VPNCORE_SRC_DIR}/vpn_dns_resolver.cpp
        ${VPNCORE_SRC_DIR}/vpn_connection.cpp
        ${VPNCORE_SRC_DIR}/connection_statistics.cpp
)


if(NOT TARGET vpnlibs_common)
    add_subdirectory(${VPN_LIB_DIR}/common ${CMAKE_BINARY_DIR}/common)
endif(NOT TARGET vpnlibs_common)

if(NOT TARGET vpnlibs_net)
    add_subdirectory(${VPN_LIB_DIR}/net ${CMAKE_BINARY_DIR}/net)
endif(NOT TARGET vpnlibs_net)

add_library(vpnlibs_core STATIC EXCLUDE_FROM_ALL ${SOURCE_FILES})
set_target_properties(vpnlibs_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
if (NOT MSVC)
    target_compile_options(vpnlibs_core PRIVATE -W -Wall -Wextra -Werror)
    target_compile_options(vpnlibs_core PRIVATE
            -Wno-unknown-warning-option -Wno-macro-redefined -Wno-unused-parameter
            -Wno-missing-field-initializers -Wno-c99-designator)
else()
    target_compile_definitions(vpnlibs_core PRIVATE _UNICODE UNICODE)
endif()

target_include_directories(vpnlibs_core PUBLIC include)

find_package(klib REQUIRED)
find_package(magic_enum REQUIRED)
find_package(libevent REQUIRED)
find_package(dns-libs REQUIRED)
find_package(quiche REQUIRED)

target_link_libraries(vpnlibs_core vpnlibs_common vpnlibs_net)
target_link_libraries(vpnlibs_core klib::klib magic_enum::magic_enum libevent::libevent)
target_link_libraries(vpnlibs_core dns-libs::dns-libs quiche::quiche)
if (WIN32)
    target_link_libraries(vpnlibs_core BCrypt) # Quiche requirement
endif()
if (APPLE)
    find_package(ghc_filesystem REQUIRED)
    target_link_libraries(vpnlibs_core ghcFilesystem::ghc_filesystem)
endif()

if(NOT TARGET vpnlibs_tcpip)
    add_subdirectory(${VPN_LIB_DIR}/tcpip ${CMAKE_BINARY_DIR}/tcpip)
endif(NOT TARGET vpnlibs_tcpip)

target_link_libraries(vpnlibs_core vpnlibs_tcpip)

set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)


if (NOT MSVC)
add_compile_options(-Wall -Wextra -Werror -Wimplicit-fallthrough
        -Wno-missing-field-initializers -Wno-unused-parameter -Wno-c99-designator -Wno-unused-private-field)
endif()

enable_testing()

link_libraries(gtest::gtest)
include(${VPN_LIB_DIR}/cmake/add_unit_test.cmake)
set(TEST_EXTRA_INCLUDES ${VPNCORE_SRC_DIR} ${THIRD_PARTY_DIR}/klib)

# do not link `VpnClient` tests against the mocked library as it mocks `VpnClient` also
add_unit_test(test_vpn_client_fsm "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
target_link_libraries(test_vpn_client_fsm PRIVATE vpnlibs_core)
add_unit_test(test_vpn_client_live "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
target_link_libraries(test_vpn_client_live PRIVATE vpnlibs_core)
add_unit_test(test_dns_routing "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
target_link_libraries(test_dns_routing PRIVATE vpnlibs_core)

set(MOCKED_SOURCE_FILES
        ${SOURCE_FILES}
        ${TEST_DIR}/test_mock_c.cpp
        ${TEST_DIR}/test_mock_vpn_client.cpp
)
list(REMOVE_ITEM MOCKED_SOURCE_FILES
        ${VPNCORE_SRC_DIR}/vpn_client.cpp
)
add_library(vpnlibs_core_mocked STATIC EXCLUDE_FROM_ALL
        ${MOCKED_SOURCE_FILES}
    )

if (MSVC)
    target_compile_definitions(vpnlibs_core_mocked PRIVATE _UNICODE UNICODE)
endif (MSVC)

set(MOCKED_FUNCTIONS
        locations_pinger_start
    )

foreach(FN ${MOCKED_FUNCTIONS})
    target_compile_definitions(vpnlibs_core_mocked PRIVATE ${FN}=MOCK_${FN})
endforeach(FN ${MOCKED_FUNCTIONS})

target_link_libraries(vpnlibs_core_mocked vpnlibs_common vpnlibs_net vpnlibs_tcpip)
target_link_libraries(vpnlibs_core_mocked klib::klib magic_enum::magic_enum libevent::libevent)
target_link_libraries(vpnlibs_core_mocked dns-libs::dns-libs)
target_link_libraries(vpnlibs_core_mocked quiche::quiche)
if (WIN32)
    target_link_libraries(vpnlibs_core_mocked BCrypt) # Quiche requirement
endif()
if (APPLE)
    find_package(ghc_filesystem REQUIRED)
    target_link_libraries(vpnlibs_core_mocked ghcFilesystem::ghc_filesystem)
endif()
target_include_directories(vpnlibs_core_mocked PUBLIC include)

link_libraries(vpnlibs_core_mocked)
target_include_directories(vpnlibs_core_mocked PUBLIC ${TEST_EXTRA_INCLUDES})

add_unit_test(test_domain_filter "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE FALSE)
add_unit_test(test_utils "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE FALSE)
add_unit_test(test_domain_lookuper "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE FALSE)

add_unit_test(test_tunnel "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_memory_buffer "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_memfile_buffer "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_upstream_multiplexer "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_single_upstream_connector "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_fallbackable_upstream_connector "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_vpn_dns_resolver "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_quic_connection_migration "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_connection_statistics "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_http_udp_multiplexer "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)

add_unit_test(test_vpn_manager_fsm ${TEST_DIR} "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
add_unit_test(test_vpn_manager_fsm_recovery ${TEST_DIR} "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
