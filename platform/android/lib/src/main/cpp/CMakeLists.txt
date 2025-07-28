cmake_minimum_required(VERSION 3.22.1)

set(ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../)

if(NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES ${ROOT_DIR}/cmake/conan_bootstrap.cmake)
endif()

set(CMAKE_CXX_STANDARD 20)

project("trusttunnel_android")

add_library(${CMAKE_PROJECT_NAME} SHARED
    lib.cpp
    native_logger.cpp
    jni_utils.cpp)


add_subdirectory(${ROOT_DIR} ${CMAKE_BINARY_DIR}/standalone)

target_link_libraries(${CMAKE_PROJECT_NAME} android log vpnlibs_standalone)
