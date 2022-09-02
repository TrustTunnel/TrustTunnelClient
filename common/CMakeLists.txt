cmake_minimum_required(VERSION 3.0)
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

include(../cmake/conan_bootstrap.cmake)
conan_bootstrap(SRCROOT ".." CONANFILE "../conanfile.py" SCOPE_NAME agvpn)

set(SOURCE_FILES
        ${COMMON_SRC_DIR}/utils.cpp
        ${COMMON_SRC_DIR}/fsm.cpp
        ${COMMON_SRC_DIR}/fsm_validation.cpp
        ${COMMON_SRC_DIR}/event_loop.cpp
        ${COMMON_SRC_DIR}/platform.cpp
)

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
target_link_libraries(vpnlibs_common
        CONAN_PKG::native_libs_common CONAN_PKG::libevent
        CONAN_PKG::magic_enum CONAN_PKG::dns-libs)
if (MSVC)
    target_link_libraries(vpnlibs_common Ws2_32 crypt32 UserEnv)
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
