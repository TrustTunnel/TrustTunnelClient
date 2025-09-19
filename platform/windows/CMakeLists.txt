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

if (NOT TARGET vpnlibs_standalone)
    add_subdirectory(${ROOT_DIR} ${CMAKE_BINARY_DIR}/standalone)
endif ()

add_library(vpn_easy_a STATIC EXCLUDE_FROM_ALL src/vpn_easy.cpp)
target_include_directories(vpn_easy_a PUBLIC include)
target_link_libraries(vpn_easy_a vpnlibs_standalone)

add_library(vpn_easy SHARED src/vpn_easy.cpp)
target_link_libraries(vpn_easy vpn_easy_a)

add_executable(vpn_easy_test EXCLUDE_FROM_ALL test/vpn_easy_test.cpp)
target_link_libraries(vpn_easy_test vpn_easy_a)
