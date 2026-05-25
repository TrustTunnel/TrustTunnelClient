# TrustTunnelClientWindows CMake package config
# This file is consumed by find_package(TrustTunnelClientWindows) or via FetchContent.
#
# Provided targets:
#   TrustTunnelClientWindows::vpn_easy        - Shared library (DLL) for VPN adapter API
#   TrustTunnelClientWindows::vpn_easy_service - Executable for VPN Windows service
#
# The shared library (vpn_easy.dll) contains all transitive dependencies linked
# in at build time — the consumer does not need to provide any third-party libs.
# At link time, only the import library (vpn_easy.lib) is needed.  At runtime,
# vpn_easy.dll must be on the DLL search path (e.g., next to the executable).
#
# Usage:
#   find_package(TrustTunnelClientWindows REQUIRED)
#   target_link_libraries(myapp PRIVATE TrustTunnelClientWindows::vpn_easy)

# Resolve all paths relative to this config file's location.
# The layout is: <prefix>/lib/cmake/TrustTunnelClientWindows/TrustTunnelClientWindowsConfig.cmake
set(_INSTALL_PREFIX "${CMAKE_CURRENT_LIST_DIR}/../../..")

# --- TrustTunnelClientWindows::vpn_easy (shared library) ---
if(NOT TARGET TrustTunnelClientWindows::vpn_easy)
    add_library(TrustTunnelClientWindows::vpn_easy SHARED IMPORTED)
    set_target_properties(TrustTunnelClientWindows::vpn_easy PROPERTIES
        IMPORTED_LOCATION "${_INSTALL_PREFIX}/bin/vpn_easy.dll"
        IMPORTED_IMPLIB "${_INSTALL_PREFIX}/lib/vpn_easy.lib"
        INTERFACE_INCLUDE_DIRECTORIES "${_INSTALL_PREFIX}/include"
    )
endif()

# --- TrustTunnelClientWindows::vpn_easy_service (executable) ---
if(NOT TARGET TrustTunnelClientWindows::vpn_easy_service)
    add_executable(TrustTunnelClientWindows::vpn_easy_service IMPORTED)
    set_target_properties(TrustTunnelClientWindows::vpn_easy_service PROPERTIES
        IMPORTED_LOCATION "${_INSTALL_PREFIX}/bin/vpn_easy_service.exe"
    )
endif()
