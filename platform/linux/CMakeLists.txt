cmake_minimum_required(VERSION 3.24)
project(trusttunnel_linux LANGUAGES C CXX)

# The daemon links the real TrustTunnel core, so it can only be built as part of the
# repository root project.
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    message(FATAL_ERROR "platform/linux: standalone build is not supported, build from the repository root \
(see platform/linux/README.md)")
endif ()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT MSVC)
    add_compile_options(-Wall -Wextra -Wpedantic)
endif ()

find_package(PkgConfig REQUIRED)
pkg_check_modules(Libsystemd IMPORTED_TARGET libsystemd)
if (NOT TARGET PkgConfig::Libsystemd)
    message(STATUS "platform/linux: libsystemd not found - skipping")
    return ()
endif ()
find_package(Threads REQUIRED)

set(TRUSTTUNNEL_LINUX_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Daemon executable
add_executable(trusttunneld
    src/main.cpp
    src/vpn_controller.cpp
)

target_include_directories(trusttunneld PRIVATE ${TRUSTTUNNEL_LINUX_INCLUDE_DIR})
target_link_libraries(trusttunneld
    PRIVATE
        PkgConfig::Libsystemd
        Threads::Threads
        vpnlibs_trusttunnel
)

# Generate systemd service file with absolute binary path
include(GNUInstallDirs)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/trusttunneld.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/trusttunneld.service
    @ONLY
)

# Installation targets
install(TARGETS trusttunneld DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/trusttunneld.service DESTINATION lib/systemd/system)
install(FILES resources/com.adguard.TrustTunnel.conf DESTINATION share/dbus-1/system.d)
install(FILES resources/com.adguard.TrustTunnel.xml DESTINATION share/dbus-1/interfaces)

# Unit testing
include(CTest)
if (BUILD_TESTING)
    find_package(GTest REQUIRED)
    add_executable(vpn_controller_test
        test/vpn_controller_test.cpp
        src/vpn_controller.cpp
    )
    target_include_directories(vpn_controller_test PRIVATE ${TRUSTTUNNEL_LINUX_INCLUDE_DIR})
    target_link_libraries(vpn_controller_test
        PRIVATE
            PkgConfig::Libsystemd
            Threads::Threads
            vpnlibs_trusttunnel
            gtest::gtest
    )
    add_test(NAME vpn_controller_test COMMAND vpn_controller_test)
    add_dependencies(tests vpn_controller_test)
endif ()
