cmake_minimum_required(VERSION 3.24)

set(ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)

if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR AND NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
    # Must be set before the first project() call so the Conan provider is active
    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "${ROOT_DIR}/cmake/conan_bootstrap.cmake")
endif ()

project(trusttunnel_linux LANGUAGES C CXX)

if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    # Standalone build: pull in the repository root for vpnlibs_trusttunnel, just like the other
    # platform adapters do. The repository root never adds this directory on its own.
    if (NOT TARGET vpnlibs_trusttunnel)
        add_subdirectory(${ROOT_DIR} ${CMAKE_BINARY_DIR}/trusttunnel)
    endif ()
endif ()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT MSVC)
    add_compile_options(-Wall -Wextra -Wpedantic)
endif ()

find_package(Threads REQUIRED)

set(TRUSTTUNNEL_LINUX_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# ---------------------------------------------------------------------------
# Client library (static). Consumers link this and drive the client through the C API
# from include/trusttunnel/trusttunnel.h. It is static because the Conan dependencies are
# built without -fPIC, so they cannot be linked into a shared object here.
# ---------------------------------------------------------------------------
add_library(trusttunnel_linux STATIC
    src/trusttunnel.cpp
    src/vpn_controller.cpp
)
target_include_directories(trusttunnel_linux
    PUBLIC
        ${TRUSTTUNNEL_LINUX_INCLUDE_DIR}/include
    PRIVATE
        ${TRUSTTUNNEL_LINUX_INCLUDE_DIR}
)
target_link_libraries(trusttunnel_linux
    PUBLIC
        vpnlibs_trusttunnel
        Threads::Threads
)
set_target_properties(trusttunnel_linux PROPERTIES
    OUTPUT_NAME trusttunnel
)

# ---------------------------------------------------------------------------
# Installation rules: the layout doubles as the artifact archive contract.
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS trusttunnel_linux
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/trusttunnel
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Generate the package config relative to the actual install layout, so multiarch/lib64 prefixes work.
set(TT_LINUX_PACKAGE_CONFIG_LIB_DIR "${CMAKE_INSTALL_LIBDIR}")
set(TT_LINUX_PACKAGE_CONFIG_INCLUDE_DIR "${CMAKE_INSTALL_INCLUDEDIR}")
include(CMakePackageConfigHelpers)
configure_package_config_file(
    cmake/TrustTunnelClientLinuxConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/TrustTunnelClientLinuxConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TrustTunnelClientLinux
    PATH_VARS TT_LINUX_PACKAGE_CONFIG_LIB_DIR TT_LINUX_PACKAGE_CONFIG_INCLUDE_DIR
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/TrustTunnelClientLinuxConfig.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TrustTunnelClientLinux
)
install(FILES ${ROOT_DIR}/LICENSE DESTINATION .)

# ---------------------------------------------------------------------------
# Unit testing
# ---------------------------------------------------------------------------
include(CTest)
if (BUILD_TESTING)
    find_package(GTest REQUIRED)

    set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
    include(${ROOT_DIR}/cmake/add_unit_test.cmake)

    # Tests include the library's private headers via "src/..." and link the static
    # library as a whole (its PUBLIC deps propagate vpnlibs_trusttunnel and Threads)
    add_unit_test(trusttunnel_capi_test "${TEST_DIR}" "${TRUSTTUNNEL_LINUX_INCLUDE_DIR}" TRUE TRUE)
    target_link_libraries(trusttunnel_capi_test PRIVATE trusttunnel_linux)

    add_unit_test(vpn_controller_test "${TEST_DIR}" "${TRUSTTUNNEL_LINUX_INCLUDE_DIR}" TRUE TRUE)
    target_link_libraries(vpn_controller_test PRIVATE trusttunnel_linux)
endif ()
