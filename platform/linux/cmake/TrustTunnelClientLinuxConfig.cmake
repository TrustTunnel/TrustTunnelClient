# TrustTunnelClientLinux package config.
#
# Consumed via `find_package(TrustTunnelClientLinux PATHS <extracted archive>/lib/cmake)`.
# Defines imported targets for the static libraries shipped in
# trusttunnel-client-linux-<version>-<arch>.zip:
#
#   trusttunnel::trusttunnel - the VPN client C API (include/trusttunnel/trusttunnel.h)
#   trusttunnel::deeplink    - the deeplink C API (include/trusttunnel/trusttunnel_deeplink.h),
#                              defined only when the library is present in the package

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)

if (NOT TARGET trusttunnel::trusttunnel)
    add_library(trusttunnel::trusttunnel STATIC IMPORTED)
    set_target_properties(trusttunnel::trusttunnel PROPERTIES
        IMPORTED_LOCATION "${PACKAGE_PREFIX_DIR}/lib/libtrusttunnel.a"
        INTERFACE_INCLUDE_DIRECTORIES "${PACKAGE_PREFIX_DIR}/include"
    )
endif ()

if (EXISTS "${PACKAGE_PREFIX_DIR}/lib/libtrusttunnel_deeplink_ffi.a" AND NOT TARGET trusttunnel::deeplink)
    add_library(trusttunnel::deeplink STATIC IMPORTED)
    set_target_properties(trusttunnel::deeplink PROPERTIES
        IMPORTED_LOCATION "${PACKAGE_PREFIX_DIR}/lib/libtrusttunnel_deeplink_ffi.a"
        INTERFACE_INCLUDE_DIRECTORIES "${PACKAGE_PREFIX_DIR}/include"
        # Transitive system dependencies of the Rust standard library: without these the
        # consumer's link fails with undefined references to pthread_create/dlsym
        INTERFACE_LINK_LIBRARIES "pthread;dl;m"
    )
endif ()
