cmake_minimum_required(VERSION 3.24)
project(core C CXX)

include(ExternalProject)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

set(VPN_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(VPN_CORE_DIR ${VPN_LIB_DIR}/core)

if (MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Zi /EHs-c- /W0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Zi /EHs-c- /std:c++latest /W0")
endif (MSVC)

set(SOURCE_FILES
        src/config.cpp
        src/client.cpp
        src/utils.cpp
        src/connection_info.cpp
        )

add_library(vpnlibs_trusttunnel EXCLUDE_FROM_ALL ${SOURCE_FILES})
target_include_directories(vpnlibs_common PUBLIC include)

find_package(cxxopts REQUIRED)
find_package(native_libs_common REQUIRED)
find_package(magic_enum REQUIRED)
find_package(native_libs_common REQUIRED)
find_package(tomlplusplus REQUIRED)
find_package(nlohmann_json REQUIRED)

target_link_libraries(vpnlibs_trusttunnel vpnlibs_core cxxopts::cxxopts)
target_link_libraries(vpnlibs_trusttunnel magic_enum::magic_enum)
target_link_libraries(vpnlibs_trusttunnel native_libs_common::native_libs_common)
target_link_libraries(vpnlibs_trusttunnel tomlplusplus::tomlplusplus)
target_link_libraries(vpnlibs_trusttunnel nlohmann_json::nlohmann_json)
if (NOT MSVC)
    target_compile_options(vpnlibs_trusttunnel PRIVATE "-fno-exceptions")
endif (NOT MSVC)

target_compile_definitions(vpnlibs_trusttunnel PUBLIC TOML_EXCEPTIONS=0)
target_compile_definitions(vpnlibs_trusttunnel PUBLIC _HAS_EXCEPTIONS=0)
target_compile_definitions(vpnlibs_trusttunnel PUBLIC CXXOPTS_NO_RTTI=1 CXXOPTS_NO_EXCEPTIONS=1)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "mips.*")
    target_link_libraries(vpnlibs_trusttunnel atomic)
endif ()

if (CMAKE_C_COMPILER MATCHES ".*-musl(eabi)?(sf)?-.*")
    add_link_options(-static -Wl,--allow-multiple-definition)
    target_link_libraries(vpnlibs_trusttunnel atomic)
endif ()

set(EXE_SOURCE_FILES
        src/trusttunnel_client.cpp
)

if (APPLE)
    list(APPEND EXE_SOURCE_FILES
            src/AppleSleepNotifier.mm
    )
endif ()

add_executable(trusttunnel_client EXCLUDE_FROM_ALL ${EXE_SOURCE_FILES})
target_link_libraries(trusttunnel_client vpnlibs_trusttunnel)
if (NOT MSVC)
    target_compile_options(trusttunnel_client PRIVATE "-fno-exceptions")
endif (NOT MSVC)

if (APPLE)
    target_link_libraries(trusttunnel_client "-framework IOKit")
endif ()

if (WIN32)
    set(WIZARD_EXE_NAME setup_wizard.exe)
else (WIN32)
    set(WIZARD_EXE_NAME setup_wizard)
endif (WIN32)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(TARGET_SUBDIR debug)
else ()
    set(CARGO_BUILD_TYPE --release)
    set(TARGET_SUBDIR release)
endif ()

if (APPLE)
    if (CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
        set(CARGO_TARGET --target x86_64-apple-darwin)
        set(TARGET_SUBDIR "x86_64-apple-darwin/${TARGET_SUBDIR}")
    elseif (CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
        set(CARGO_TARGET --target aarch64-apple-darwin)
        set(TARGET_SUBDIR "aarch64-apple-darwin/${TARGET_SUBDIR}")
    endif ()
endif (APPLE)

ExternalProject_Add(setup_wizard
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/setup_wizard
        BUILD_ALWAYS TRUE
        UPDATE_COMMAND ""
        PATCH_COMMAND ""
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ${CMAKE_COMMAND} -E env CARGO_BUILD_TARGET_DIR=<BINARY_DIR> cargo build
        BUILD_COMMAND     --manifest-path=<SOURCE_DIR>/Cargo.toml ${CARGO_BUILD_TYPE} ${CARGO_TARGET}
        BUILD_COMMAND     --bin setup_wizard
        TEST_COMMAND ""
        INSTALL_COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_SUBDIR}/${WIZARD_EXE_NAME} ${CMAKE_CURRENT_BINARY_DIR}
        )

add_custom_target(run_setup_wizard)
add_custom_command(
        TARGET run_setup_wizard
        POST_BUILD
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${WIZARD_EXE_NAME}
        USES_TERMINAL TRUE
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
add_dependencies(run_setup_wizard setup_wizard)

enable_testing()
add_dependencies(tests
        trusttunnel_client
        vpnlibs_trusttunnel
        setup_wizard
        )
