cmake_minimum_required(VERSION 3.24)
project(common)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

find_package(Threads REQUIRED)

if(CMAKE_USE_PTHREADS_INIT)
    add_compile_options("-pthread")
endif()

set(VPN_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(COMMON_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(THIRD_PARTY_DIR ${VPN_LIB_DIR}/third-party)

set(SOURCE_FILES
        ${COMMON_SRC_DIR}/utils.cpp
        ${COMMON_SRC_DIR}/fsm.cpp
        ${COMMON_SRC_DIR}/fsm_validation.cpp
        ${COMMON_SRC_DIR}/event_loop.cpp
        ${COMMON_SRC_DIR}/platform.cpp
)

if (WIN32)
    list(APPEND SOURCE_FILES ${COMMON_SRC_DIR}/guid_utils.cpp)
endif()

add_library(vpnlibs_common STATIC EXCLUDE_FROM_ALL ${SOURCE_FILES})
set_property(TARGET vpnlibs_common PROPERTY POSITION_INDEPENDENT_CODE ON)
if (NOT MSVC)
    target_compile_options(vpnlibs_common PRIVATE -W -Wall -Wextra -Werror)
    target_compile_options(vpnlibs_common PRIVATE
            -Wno-unknown-warning-option -Wno-macro-redefined -Wno-unused-parameter
            -Wno-missing-field-initializers -Wno-c99-designator)
endif()
target_include_directories(vpnlibs_common PUBLIC include)
target_link_libraries(vpnlibs_common ${CMAKE_THREAD_LIBS_INIT})

find_package(native_libs_common REQUIRED)
find_package(libevent REQUIRED)
find_package(magic_enum REQUIRED)
find_package(dns-libs REQUIRED)
target_link_libraries(vpnlibs_common
        native_libs_common::native_libs_common libevent::libevent
        magic_enum::magic_enum dns-libs::dns-libs)
if (MSVC)
    target_link_libraries(vpnlibs_common Ws2_32 crypt32 UserEnv Version)
    # Needed as fmt headers leak through the DNS proxy headers
    target_compile_definitions(vpnlibs_common PUBLIC FMT_EXCEPTIONS=0)
endif()


enable_testing()

link_libraries(vpnlibs_common)
include(../cmake/add_unit_test.cmake)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

add_unit_test(test_fsm "${TEST_DIR}" "${COMMON_SRC_DIR}" TRUE TRUE)
add_unit_test(test_event_loop "${TEST_DIR}" "${COMMON_SRC_DIR}" TRUE TRUE)
add_unit_test(test_dns_stamp "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)

if (WIN32)
    add_unit_test(test_guid "${TEST_DIR}" "${TEST_EXTRA_INCLUDES}" TRUE TRUE)
endif()
