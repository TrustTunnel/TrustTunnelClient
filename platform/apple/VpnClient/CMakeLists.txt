cmake_minimum_required(VERSION 3.24)

set(ROOT_DIR ../../..)
if(NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "${ROOT_DIR}/cmake/conan_bootstrap.cmake")
endif()

set(TARGET_OS "macos" CACHE STRING "Target OS")

string(TOLOWER "${TARGET_OS}" TARGET_OS)

if (CMAKE_OSX_SYSROOT STREQUAL "iphonesimulator")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "Minimum iOS deployment version")
    set(INFOPLIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.ios")
elseif ("${TARGET_OS}" STREQUAL "macos")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum macOS deployment version")
    set(INFOPLIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.macos")
elseif ("${TARGET_OS}" STREQUAL "ios")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "Minimum iOS deployment version")
    set(CMAKE_XCODE_ATTRIBUTE_BITCODE_GENERATION_MODE bitcode CACHE INTERNAL "")
    add_compile_options(-fembed-bitcode)
    set(INFOPLIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.ios")
else()
    message(FATAL_ERROR "unknown os: ${TARGET_OS}")
endif()

project(VpnClientFramework CXX OBJCXX)

# Ensure that API is compatible with minimum MacOS version
add_compile_options(-Werror=unguarded-availability)
link_libraries(-Wl,-application_extension)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)


add_compile_options(-fno-strict-aliasing -fno-exceptions -fobjc-abi-version=2 -fno-omit-frame-pointer)

add_subdirectory(${ROOT_DIR} ${CMAKE_BINARY_DIR}/standalone)

add_library(${PROJECT_NAME} SHARED
    VpnClient.h
    VpnClient.mm
    module.modulemap
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    FRAMEWORK TRUE
    FRAMEWORK_VERSION A
    VERSION 0.99.31
    PUBLIC_HEADER VpnClient.h
    MACOSX_FRAMEWORK_INFO_PLIST "${INFOPLIST_FILE}"
    MACOSX_FRAMEWORK_IDENTIFIER com.adguard.TrustTunnel.VpnClientFramework
    INSTALL_NAME_DIR "@rpath"
    BUILD_WITH_INSTALL_RPATH 1
    COMPILE_FLAGS "-fobjc-arc"
)

target_link_options(${PROJECT_NAME} PRIVATE "-ObjC")

target_link_libraries(${PROJECT_NAME} vpnlibs_standalone)

target_link_libraries(${PROJECT_NAME} "-framework Foundation" "-framework NetworkExtension")

set_property(SOURCE module.modulemap PROPERTY MACOSX_PACKAGE_LOCATION "Modules")
if ("${TARGET_OS}" STREQUAL "macos")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E create_symlink "Versions/Current/Modules" "$<TARGET_BUNDLE_DIR:VpnClientFramework>/Modules")
            target_link_libraries(${PROJECT_NAME} "-framework AppKit")
endif ()

