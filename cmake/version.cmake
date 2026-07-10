# Resolves the project version once per CMake run and exposes (as global cache
# variables, so every directory scope and add_subdirectory sees them):
#   TT_CLIENT_VERSION_FULL    free-form version (e.g. 1.2.3, 1.2.3-beta.4,
#                             1.2.3-6-gabcdef)
#   TT_CLIENT_VERSION_CORE    numeric X.Y.Z only (prerelease/build suffix dropped)
#   TT_CLIENT_VERSION_COMMAS  core with ',' (Windows FILEVERSION/PRODUCTVERSION)
#
# Source order:
#   1. -DTT_CLIENT_VERSION=<value> cache/var override (conan passes self.version);
#   2. the TT_CLIENT_VERSION environment variable (CI sets it once per job);
#   3. git describe --tags --match 'v*' (a plain local build is self-versioning);
#   4. 0.0.0-git fallback (configure-time warning; the build never hard-fails).
include_guard(GLOBAL)

set(_tt_version "")

# 1. cache / normal variable override (e.g. conan's -DTT_CLIENT_VERSION).
if (DEFINED TT_CLIENT_VERSION AND NOT "${TT_CLIENT_VERSION}" STREQUAL "")
    set(_tt_version "${TT_CLIENT_VERSION}")
endif ()

# 2. environment variable (the single CI override, set once per job).
if (_tt_version STREQUAL "" AND NOT "$ENV{TT_CLIENT_VERSION}" STREQUAL "")
    set(_tt_version "$ENV{TT_CLIENT_VERSION}")
endif ()

# 3. git describe (no .git in conan/tarball checkouts -> falls through to step 4).
if (_tt_version STREQUAL "")
    find_package(Git QUIET)
    if (GIT_FOUND)
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" describe --tags --match "v*"
            WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/.."
            OUTPUT_VARIABLE _tt_git_describe
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            RESULT_VARIABLE _tt_git_result)
        if (_tt_git_result EQUAL 0 AND NOT _tt_git_describe STREQUAL "")
            string(REGEX REPLACE "^v" "" _tt_version "${_tt_git_describe}")
        endif ()
    endif ()
endif ()

# 4. fallback.
if (_tt_version STREQUAL "")
    set(_tt_version "0.0.0-git")
    message(WARNING "TT_CLIENT_VERSION not provided and git describe failed; "
                    "falling back to ${_tt_version}")
endif ()

# Core = leading X.Y.Z, dropping any -prerelease / +build suffix.
if (_tt_version MATCHES "^([0-9]+\\.[0-9]+\\.[0-9]+)")
    set(_tt_core "${CMAKE_MATCH_1}")
else ()
    set(_tt_core "0.0.0")
endif ()
string(REPLACE "." "," _tt_commas "${_tt_core}")

# Publish as global cache vars (include_guard makes the body run once, but with
# CACHE INTERNAL the values stay visible across every directory scope).
set(TT_CLIENT_VERSION_FULL "${_tt_version}" CACHE INTERNAL "TrustTunnel client full version")
set(TT_CLIENT_VERSION_CORE "${_tt_core}" CACHE INTERNAL "TrustTunnel client core version (X.Y.Z)")
set(TT_CLIENT_VERSION_COMMAS "${_tt_commas}" CACHE INTERNAL "TrustTunnel client core version, comma-separated")

message(STATUS "TrustTunnel client version: ${TT_CLIENT_VERSION_FULL} (core ${TT_CLIENT_VERSION_CORE})")
