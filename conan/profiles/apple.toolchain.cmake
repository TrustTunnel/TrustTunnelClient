# Set minimum deployment version
if(CMAKE_OSX_SYSROOT STREQUAL iphonesimulator)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0" CACHE STRING "Minimum iOS deployment version")
elseif(CMAKE_OSX_SYSROOT STREQUAL iphoneos)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0" CACHE STRING "Minimum iOS deployment version")
    add_compile_options(-fembed-bitcode)
else()
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum macOS deployment version")
endif()

# We don't need to export any symbol implicitly, and also disable C++ exceptions.
set(CMAKE_C_FLAGS_INIT "${CMAKE_C_FLAGS_INIT} -fvisibility=hidden -fno-exceptions")
set(CMAKE_CXX_FLAGS_INIT "${CMAKE_CXX_FLAGS_INIT} -fvisibility=hidden -fno-exceptions")
