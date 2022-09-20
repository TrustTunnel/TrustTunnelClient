# Get ${CMAKE_PLATFORM_INFO_DIR}/../.. and ../../.. . Need to use get_filename_component because CMAKE_PLATFORM_INFO_DIR
# may not be created yet.
get_filename_component(CMAKE_PLATFORM_INFO_DIR_PARENT "${CMAKE_PLATFORM_INFO_DIR}" DIRECTORY)
get_filename_component(CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT "${CMAKE_PLATFORM_INFO_DIR_PARENT}" DIRECTORY)
get_filename_component(CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT_PARENT "${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT}" DIRECTORY)
# Verbose only on first run
if(EXISTS "${CMAKE_PLATFORM_INFO_DIR}")
set(QUIET ON)
endif()

# Load conan build info
if(EXISTS "${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT}/conanbuildinfo.cmake")
    include("${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT}/conanbuildinfo.cmake")
    if(NOT QUIET)
        message("included ${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT}/conanbuildinfo.cmake")
    endif(NOT QUIET)
elseif(EXISTS "${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT_PARENT}/conanbuildinfo.cmake")
    include("${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT_PARENT}/conanbuildinfo.cmake")
    if(NOT QUIET)
        message("included ${CMAKE_PLATFORM_INFO_DIR_PARENT_PARENT_PARENT}/conanbuildinfo.cmake")
    endif(NOT QUIET)
else()
message(FATAL_ERROR "conanbuildinfo.cmake not found, make sure that conan install finished correctly.")
endif()
if(NOT QUIET)
    message("ARCH: ${CONAN_SETTINGS_ARCH}")
endif(NOT QUIET)

# Set OSX sysroot
if(CONAN_SETTINGS_OS STREQUAL "iOS")
    if(CONAN_SETTINGS_OS_SDK)
        set(CMAKE_OSX_SYSROOT "${CONAN_SETTINGS_OS_SDK}")
        if(NOT QUIET)
            message("CMAKE_OSX_SYSROOT is ${CMAKE_OSX_SYSROOT}")
        endif(NOT QUIET)
    else()
        message(FATAL_ERROR "Please specify sdk via os.sdk (iphoneos or iphonesimulator) when compiling for iOS")
    endif()
endif()

# Set system processor
if(CONAN_SETTINGS_ARCH STREQUAL "armv8")
    set(CMAKE_SYSTEM_PROCESSOR arm64)
    # CMake bug workaround
    set(CMAKE_HOST_SYSTEM_PROCESSOR arm64)
elseif(CONAN_SETTINGS_ARCH STREQUAL "x86_64")
    set(CMAKE_SYSTEM_PROCESSOR x86_64)
    # CMake bug workaround
    set(CMAKE_HOST_SYSTEM_PROCESSOR x86_64)
else()
    message(FATAL_ERROR "Architecture ${CONAN_SETTINGS_ARCH} is not supported")
endif()
set(CMAKE_OSX_ARCHITECTURES "${CMAKE_SYSTEM_PROCESSOR}")
set(CMAKE_CROSSCOMPILING TRUE)
foreach(arch ${CMAKE_OSX_ARCHITECTURES})
    add_compile_options(-arch ${arch})
    link_libraries("-arch ${arch}")
endforeach()
if(NOT QUIET)
    message("CMAKE_OSX_ARCHITECTURES is ${CMAKE_OSX_ARCHITECTURES}")
endif(NOT QUIET)

# Set minimum deployment version
if(CMAKE_OSX_SYSROOT STREQUAL iphonesimulator)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "11.2" CACHE STRING "Minimum iOS deployment version")
elseif(CMAKE_OSX_SYSROOT STREQUAL iphoneos)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "11.2" CACHE STRING "Minimum iOS deployment version")
    add_compile_options(-fembed-bitcode)
else()
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13" CACHE STRING "Minimum macOS deployment version")
endif()

# We don't need to export any symbol implicitly, and also disable C++ exceptions.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -fno-exceptions")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fno-exceptions")
