cmake_minimum_required(VERSION 3.24)

set(ROOT_DIR ../..)

if(NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "${ROOT_DIR}/cmake/conan_bootstrap.cmake")
endif()

project(vpn_easy)

set(CMAKE_C_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
    add_compile_options(/W4)
    add_link_options(/W4)
else ()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif ()

if (NOT TARGET vpnlibs_trusttunnel)
    add_subdirectory(${ROOT_DIR} ${CMAKE_BINARY_DIR}/trusttunnel)
endif ()

add_library(vpn_easy_a STATIC src/vpn_easy.cpp src/vpn_easy_pipe.cpp)
target_include_directories(vpn_easy_a PUBLIC include)
target_link_libraries(vpn_easy_a vpnlibs_trusttunnel)

add_library(vpn_easy SHARED src/vpn_easy.cpp)
target_link_libraries(vpn_easy vpn_easy_a)

add_executable(vpn_easy_test test/vpn_easy_test.cpp)
target_link_libraries(vpn_easy_test vpn_easy_a)

add_executable(vpn_easy_service src/vpn_easy_service.cpp)
target_link_libraries(vpn_easy_service vpn_easy_a)

add_executable(vpn_easy_service_test test/vpn_easy_service_test.cpp)
target_link_libraries(vpn_easy_service_test vpn_easy_a)
add_dependencies(vpn_easy_service_test vpn_easy_service)

enable_testing()
include(${ROOT_DIR}/cmake/add_unit_test.cmake)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)

link_libraries(vpn_easy_a)

add_unit_test(vpn_easy_pipe_test "${TEST_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/src" TRUE TRUE)
