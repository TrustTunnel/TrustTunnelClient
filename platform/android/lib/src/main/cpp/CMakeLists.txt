cmake_minimum_required(VERSION 3.24)

set(ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../)

if(NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES ${ROOT_DIR}/cmake/conan_bootstrap.cmake)
endif()

set(CMAKE_CXX_STANDARD 20)

project("trusttunnel_android")

add_library(${CMAKE_PROJECT_NAME} SHARED
    lib.cpp
    native_logger.cpp
    jni_utils.cpp
    deeplink.cpp
    persistent_ring_buffer_jni.cpp)


add_subdirectory(${ROOT_DIR} ${CMAKE_BINARY_DIR}/trusttunnel)

target_link_libraries(${CMAKE_PROJECT_NAME} android log vpnlibs_trusttunnel trusttunnel_deeplink_ffi)

# Allow multiple definitions from Rust static libraries (trusttunnel_deeplink_ffi and quiche)
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--allow-multiple-definition")
