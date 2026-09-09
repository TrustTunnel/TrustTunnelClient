# TrustTunnelClientWindows CMake package config
# This file is consumed by find_package(TrustTunnelClientWindows) or via FetchContent.
#
# Provided targets:
#   TrustTunnelClientWindows::trusttunnel               - Shared library (DLL) for VPN adapter API
#   TrustTunnelClientWindows::trusttunnel_service       - Executable for VPN Windows service
#   TrustTunnelClientWindows::trusttunnel_service_installer - Elevated helper for installing/uninstalling VPN service
#
# The shared library (trusttunnel.dll) contains all transitive dependencies
# linked in at build time — the consumer does not need to provide any
# third-party libs.  At link time, only the import library (trusttunnel.lib)
# is needed.  At runtime, trusttunnel.dll must be on the DLL search path
# (e.g., next to the executable).
#
# Usage:
#   find_package(TrustTunnelClientWindows REQUIRED)
#   target_link_libraries(myapp PRIVATE TrustTunnelClientWindows::trusttunnel)

# Resolve all paths relative to this config file's location.
# The layout is: <prefix>/lib/cmake/TrustTunnelClientWindows/TrustTunnelClientWindowsConfig.cmake
set(_INSTALL_PREFIX "${CMAKE_CURRENT_LIST_DIR}/../../..")

# --- TrustTunnelClientWindows::trusttunnel (shared library) ---
if(NOT TARGET TrustTunnelClientWindows::trusttunnel)
    add_library(TrustTunnelClientWindows::trusttunnel SHARED IMPORTED)
    set_target_properties(TrustTunnelClientWindows::trusttunnel PROPERTIES
        IMPORTED_LOCATION "${_INSTALL_PREFIX}/bin/trusttunnel.dll"
        IMPORTED_IMPLIB "${_INSTALL_PREFIX}/lib/trusttunnel.lib"
        INTERFACE_INCLUDE_DIRECTORIES "${_INSTALL_PREFIX}/include"
    )
endif()

# --- TrustTunnelClientWindows::trusttunnel_service (executable) ---
if(NOT TARGET TrustTunnelClientWindows::trusttunnel_service)
    add_executable(TrustTunnelClientWindows::trusttunnel_service IMPORTED)
    set_target_properties(TrustTunnelClientWindows::trusttunnel_service PROPERTIES
        IMPORTED_LOCATION "${_INSTALL_PREFIX}/bin/trusttunnel_service.exe"
    )
endif()

# --- TrustTunnelClientWindows::trusttunnel_service_installer (executable) ---
if(NOT TARGET TrustTunnelClientWindows::trusttunnel_service_installer)
    add_executable(TrustTunnelClientWindows::trusttunnel_service_installer IMPORTED)
    set_target_properties(TrustTunnelClientWindows::trusttunnel_service_installer PROPERTIES
        IMPORTED_LOCATION "${_INSTALL_PREFIX}/bin/trusttunnel_service_installer.exe"
    )
endif()
