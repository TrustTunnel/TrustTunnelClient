cmake_minimum_required(VERSION 3.24)
project(trusttunnel_linux LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT MSVC)
    add_compile_options(-Wall -Wextra -Wpedantic)
endif ()

find_package(PkgConfig REQUIRED)
pkg_check_modules(Libsystemd IMPORTED_TARGET libsystemd)
if (NOT TARGET PkgConfig::Libsystemd)
    if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
        message(FATAL_ERROR "platform/linux: libsystemd (systemd-devel) is required.")
    else ()
        message(STATUS "platform/linux: libsystemd not found - skipping")
        return ()
    endif ()
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
    find_package(GTest)
    if (TARGET GTest::gtest_main)
        add_executable(vpn_controller_test
            test/vpn_controller_test.cpp
            src/vpn_controller.cpp
        )
        target_include_directories(vpn_controller_test PRIVATE ${TRUSTTUNNEL_LINUX_INCLUDE_DIR})
        target_link_libraries(vpn_controller_test PRIVATE GTest::gtest_main Threads::Threads)
        add_test(NAME vpn_controller_test COMMAND vpn_controller_test)
    else ()
        message(STATUS "GTest not found: skipping unit tests for trusttunnel_linux")
    endif ()
endif ()
