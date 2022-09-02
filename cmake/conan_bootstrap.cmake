function(conan_bootstrap)
    cmake_parse_arguments(BS "" "SRCROOT;CONANFILE;SCOPE_NAME" "" ${ARGN})
    set(CONAN_EXPORTED OFF)
    include("${BS_SRCROOT}/cmake/conan.cmake")
    if (NOT TARGET CONAN_DONE::${BS_SCOPE_NAME})
        # Profile settings
        if(ANDROID_ABI STREQUAL armeabi-v7a)
            set(CONAN_PROFILE "${CMAKE_CURRENT_SOURCE_DIR}/${BS_SRCROOT}/conan/profiles/android-arm.jinja")
        elseif(ANDROID_ABI STREQUAL arm64-v8a)
            set(CONAN_PROFILE "${CMAKE_CURRENT_SOURCE_DIR}/${BS_SRCROOT}/conan/profiles/android-arm64.jinja")
        elseif(ANDROID_ABI STREQUAL x86)
            set(CONAN_PROFILE "${CMAKE_CURRENT_SOURCE_DIR}/${BS_SRCROOT}/conan/profiles/android-x86.jinja")
        elseif(ANDROID_ABI STREQUAL x86_64)
            set(CONAN_PROFILE "${CMAKE_CURRENT_SOURCE_DIR}/${BS_SRCROOT}/conan/profiles/android-x86_64.jinja")
        elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
            set(CONAN_PROFILE "${CMAKE_CURRENT_SOURCE_DIR}/${BS_SRCROOT}/conan/profiles/linux-clang")
        elseif(WIN32)
            if (CMAKE_C_COMPILER MATCHES ".*clang.*")
                set(CONAN_PROFILE "${CMAKE_CURRENT_SOURCE_DIR}/${BS_SRCROOT}/conan/profiles/windows-clang-cl.jinja")
            else()
                set(CONAN_PROFILE "${CMAKE_CURRENT_SOURCE_DIR}/${BS_SRCROOT}/conan/profiles/windows-msvc.jinja")
            endif()
        elseif(APPLE)
            if(NOT TARGET_OS)
                set(TARGET_OS macos)
            endif()
            set(CONAN_PROFILE "${CMAKE_CURRENT_SOURCE_DIR}/${BS_SRCROOT}/conan/profiles/apple-${TARGET_OS}.jinja")
            if(NOT CMAKE_OSX_ARCHITECTURES)
            set(CMAKE_OSX_ARCHITECTURES "${CMAKE_SYSTEM_PROCESSOR}")
            endif()
            if(CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
                list(APPEND settings arch=armv8)
            else()
                list(APPEND settings arch=x86_64)
            endif()
        else()
            set(CONAN_PROFILE "default")
        endif()

        message("CONAN_PROFILE is ${CONAN_PROFILE}")

        if(ANDROID)
            conan_cmake_run(CONANFILE "${BS_CONANFILE}"
                            PROFILE "${CONAN_PROFILE}"
                            BUILD missing
                            OUTPUT_QUIET
                            PROFILE_AUTO compiler.version compiler.libcxx
                            SETTINGS ${settings}
                            ENV CMAKE_ORIGINAL_TOOLCHAIN=${CMAKE_TOOLCHAIN_FILE})
        elseif(WIN32)
            # don't set libcxx on windows to not to mix c++ libraries
            conan_cmake_run(CONANFILE "${BS_CONANFILE}"
                            PROFILE "${CONAN_PROFILE}"
                            BUILD missing
                            PROFILE_AUTO compiler.version
                            SETTINGS ${settings})
        else()
            conan_cmake_run(CONANFILE "${BS_CONANFILE}"
                            PROFILE "${CONAN_PROFILE}"
                            BUILD missing
                            PROFILE_AUTO compiler.version compiler.libcxx
                            SETTINGS ${settings})
        endif()

        conan_define_targets()
        add_library(CONAN_DONE::${BS_SCOPE_NAME} INTERFACE IMPORTED)
    endif()
endfunction()
