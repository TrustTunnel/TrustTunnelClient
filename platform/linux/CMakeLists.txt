set(ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)

if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    # Standalone build (used by scripts/build.sh, like platform/windows): pull in the
    # repository root for vpnlibs_trusttunnel and bootstrap the Conan dependencies.
    # The flag tells the root project not to include platform/linux back.
    set(TRUSTTUNNEL_LINUX_ADAPTER ON)
    if (NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
        set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "${ROOT_DIR}/cmake/conan_bootstrap.cmake")
    endif ()
endif ()

cmake_minimum_required(VERSION 3.24)
project(trusttunnel_linux LANGUAGES C CXX)

if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR AND NOT TARGET vpnlibs_trusttunnel)
    add_subdirectory(${ROOT_DIR} ${CMAKE_BINARY_DIR}/trusttunnel)
endif ()

set(CMAKE_C_STANDARD 20)
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
# Rust deeplink FFI static library (libtrusttunnel_deeplink_ffi.a).
# The imported target is defined by the root project (trusttunnel/), which builds
# the setup_wizard workspace containing the deeplink-ffi crate.
# ---------------------------------------------------------------------------
set(TRUSTTUNNEL_DEEPLINK_HEADER ${ROOT_DIR}/trusttunnel/deeplink-ffi/include/trusttunnel_deeplink.h)

# ---------------------------------------------------------------------------
# Client library (static). Consumers link this and drive the client through the C API
# from include/trusttunnel/trusttunnel.h. Compiled as PIC so it can also be linked into
# shared objects (e.g. a GUI plugin).
# ---------------------------------------------------------------------------
add_library(trusttunnel_linux_a STATIC
    src/trusttunnel.cpp
    src/vpn_controller.cpp
)
target_include_directories(trusttunnel_linux_a
    PUBLIC
        ${TRUSTTUNNEL_LINUX_INCLUDE_DIR}/include
    PRIVATE
        ${TRUSTTUNNEL_LINUX_INCLUDE_DIR}
)
target_link_libraries(trusttunnel_linux_a
    PUBLIC
        vpnlibs_trusttunnel
        Threads::Threads
)
set_target_properties(trusttunnel_linux_a PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    OUTPUT_NAME trusttunnel
)

# ---------------------------------------------------------------------------
# Daemon executable: thin sd-bus glue over the client library.
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(Libsystemd IMPORTED_TARGET libsystemd)
if (NOT TARGET PkgConfig::Libsystemd)
    message(STATUS "platform/linux: libsystemd not found - skipping the trusttunneld daemon")
else ()
    add_executable(trusttunneld daemon/main.cpp)
    target_include_directories(trusttunneld PRIVATE ${TRUSTTUNNEL_LINUX_INCLUDE_DIR})
    target_link_libraries(trusttunneld
        PRIVATE
            trusttunnel_linux_a
            PkgConfig::Libsystemd
            Threads::Threads
    )

    # Generate systemd service file with absolute binary path
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/daemon/resources/trusttunneld.service.in
        ${CMAKE_CURRENT_BINARY_DIR}/trusttunneld.service
        @ONLY
    )

    install(TARGETS trusttunneld DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/trusttunneld.service DESTINATION lib/systemd/system)
    install(FILES daemon/resources/com.adguard.TrustTunnel.conf DESTINATION share/dbus-1/system.d)
    install(FILES daemon/resources/com.adguard.TrustTunnel.xml DESTINATION share/dbus-1/interfaces)
endif ()

# ---------------------------------------------------------------------------
# Installation rules: the layout doubles as the artifact archive contract
# (see scripts/build.sh and scripts/package.sh)
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS trusttunnel_linux_a ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/trusttunnel DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if (TARGET trusttunnel_deeplink_ffi)
    install(FILES "$<TARGET_PROPERTY:trusttunnel_deeplink_ffi,IMPORTED_LOCATION>"
        DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(FILES ${TRUSTTUNNEL_DEEPLINK_HEADER}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/trusttunnel)
endif ()
install(FILES ${ROOT_DIR}/LICENSE DESTINATION .)

# CMake package config (mirror of the Windows package layout)
install(FILES cmake/TrustTunnelClientLinuxConfig.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TrustTunnelClientLinux)

# Unit testing
include(CTest)
if (BUILD_TESTING)
    find_package(GTest REQUIRED)

    set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/add_unit_test.cmake)

    # Tests include the library's private headers via "src/..." and link the static
    # library as a whole (its PUBLIC deps propagate vpnlibs_trusttunnel and Threads)
    add_unit_test(vpn_controller_test "${TEST_DIR}" "${TRUSTTUNNEL_LINUX_INCLUDE_DIR}" TRUE TRUE)
    target_link_libraries(vpn_controller_test PRIVATE trusttunnel_linux_a)

    add_unit_test(trusttunnel_capi_test "${TEST_DIR}" "${TRUSTTUNNEL_LINUX_INCLUDE_DIR}" TRUE TRUE)
    target_link_libraries(trusttunnel_capi_test PRIVATE trusttunnel_linux_a)
endif ()
