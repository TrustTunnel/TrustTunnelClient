cmake_minimum_required(VERSION 3.24)
if(NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "cmake/conan_provider.cmake")
endif()
project(vpn_libs C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
    set(CompilerFlags CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELWITHDEBINFO
            CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE CMAKE_C_FLAGS_RELWITHDEBINFO)
    foreach (CompilerFlag ${CompilerFlags})
        string(REPLACE "/MDd" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "-MDd" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "/MTd" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "-MTd" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "-MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        string(REPLACE "/RTC1" "" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach ()

    add_compile_definitions(_WIN32_WINNT=0x0601)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)

    add_compile_options(/Oy-) # -fno-omit-frame-pointer
else ()
    add_compile_options(-fno-omit-frame-pointer)
endif ()

add_subdirectory(common)
add_subdirectory(net)
add_subdirectory(tcpip)
add_subdirectory(core)
add_subdirectory(standalone)

enable_testing()
