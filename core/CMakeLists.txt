cmake_minimum_required(VERSION 3.1)
project(core C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

set(VPN_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(THIRD_PARTY_DIR ${VPN_LIB_DIR}/third-party)
set(VPNCORE_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

include(../cmake/conan_bootstrap.cmake)
conan_bootstrap(SRCROOT ".." CONANFILE "../conanfile.py" SCOPE_NAME agvpn)

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
        ${VPNCORE_SRC_DIR}/dns_sniffer.cpp
        ${VPNCORE_SRC_DIR}/vpn_dns_resolver.cpp
        ${VPNCORE_SRC_DIR}/vpn_connection.cpp
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

target_link_libraries(vpnlibs_core vpnlibs_common vpnlibs_net)
target_link_libraries(vpnlibs_core CONAN_PKG::klib CONAN_PKG::magic_enum CONAN_PKG::libevent)
target_link_libraries(vpnlibs_core CONAN_PKG::dns-libs)
target_link_libraries(vpnlibs_core CONAN_PKG::quiche)
if (WIN32)
    target_link_libraries(vpnlibs_core BCrypt) # Quiche requirement
endif()
if (APPLE)
    target_link_libraries(vpnlibs_core CONAN_PKG::ghc-filesystem)
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

add_executable(standalone_client EXCLUDE_FROM_ALL ${TEST_DIR}/standalone_client/standalone_client.cpp)
target_link_libraries(standalone_client vpnlibs_core CONAN_PKG::cxxopts)
target_link_libraries(standalone_client CONAN_PKG::native_libs_common)
target_link_libraries(standalone_client CONAN_PKG::nlohmann_json)
target_link_libraries(standalone_client CONAN_PKG::magic_enum)


enable_testing()

link_libraries(CONAN_PKG::gtest)

add_library(module_vpncore_mocked STATIC EXCLUDE_FROM_ALL
        ${SOURCE_FILES}
        ${TEST_DIR}/test_mock_c.cpp
        ${TEST_DIR}/test_mock_vpn_client.cpp
    )

if (MSVC)
    target_compile_definitions(module_vpncore_mocked PRIVATE _UNICODE UNICODE)
endif (MSVC)

set(MOCKED_FUNCTIONS
        locations_pinger_start
    )

foreach(FN ${MOCKED_FUNCTIONS})
    target_compile_definitions(module_vpncore_mocked PRIVATE ${FN}=MOCK_${FN})
endforeach(FN ${MOCKED_FUNCTIONS})

include(${VPN_LIB_DIR}/cmake/add_unit_test.cmake)
set(TEST_EXTRA_INCLUDES ${VPNCORE_SRC_DIR} ${THIRD_PARTY_DIR}/klib)

# do not link `VpnClient` tests against the mocked library as it mocks `VpnClient` also
add_unit_test(test_vpn_client_fsm "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
target_link_libraries(test_vpn_client_fsm PRIVATE vpnlibs_core)
add_unit_test(test_vpn_client_live "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
target_link_libraries(test_vpn_client_live PRIVATE vpnlibs_core)

target_link_libraries(module_vpncore_mocked vpnlibs_core)
target_include_directories(module_vpncore_mocked PUBLIC ${TEST_EXTRA_INCLUDES})
link_libraries(module_vpncore_mocked)

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

if(NOT WIN32)
    add_unit_test(test_vpn_manager_fsm ${TEST_DIR} "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
    add_unit_test(test_vpn_manager_fsm_recovery ${TEST_DIR} "${TEST_EXTRA_INCLUDES}" TRUE TRUE)

    add_dependencies(tests standalone_client)
endif()

configure_file(test/standalone_client/standalone_client.conf ${CMAKE_CURRENT_BINARY_DIR}/standalone_client.conf COPYONLY)
