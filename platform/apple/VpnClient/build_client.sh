#!/bin/sh
set -xe
echo "PATH=$PATH"
echo "CONAN_USER_HOME=$CONAN_USER_HOME"
HELP_MSG="
Usage: build_client.sh [options...|clean]
    --tn       Target framework name
    --bp       Build directory path
    --fwp      Framework cmake project path
    --debug    Build with debug configuration
"

TARGET_OSES="${TARGET_OSES:-all}"
BUILD_DIR="${SRCROOT}/build"
FRAMEWORK_DIR="${SRCROOT}/VpnClient"

if [ -z ${TARGETNAME+x} ]; then
    TARGET_NAME="VpnClientFramework"
else
    TARGET_NAME="${TARGETNAME}"
fi

if [ "${CONFIGURATION}" = "Debug" ]; then
    BUILD_TYPE="Debug"
else
    BUILD_TYPE="RelWithDebInfo"
fi


if [ "${1}" == "clean" ]; then
    echo "Clean Build"
    rm -Rfv "${BUILD_DIR}"
    exit 0
fi


while [[ $# -gt 0 ]]; do
    case "$1" in
    --help)
        echo "${HELP_MSG}"
        exit 0
        ;;
    --tn)
        shift
        if [[ $# -gt 0 ]]; then
            TARGET_NAME=$1
        else
            echo "target name is not specified"
            echo "${HELP_MSG}"
            exit 1
        fi
        shift
        ;;
    --bp)
        shift
        if [[ $# -gt 0 ]]; then
            BUILD_DIR="$1"
        else
            echo "build path is not specified"
            echo "${HELP_MSG}"
            exit 1
        fi
        shift
        ;;
    --fwp)
        shift
        if [[ $# -gt 0 ]]; then
            FRAMEWORK_DIR="$1"
        else
            echo "framework path is not specified"
            echo "${HELP_MSG}"
            exit 1
        fi
        shift
        ;;
    --debug)
        shift
        BUILD_TYPE="Debug"
        ;;
    *)
        echo "unknown option ${1}"
        echo "${HELP_MSG}"
        exit 1
    esac
done

echo "TARGET_OSES= $TARGET_OSES"


if [ -z ${TARGET_OSES+x} ] || [ "${TARGET_OSES}" = "all" ]; then
    TARGET_OSES="iphonesimulator-arm64,iphonesimulator-x86_64,macos-x86_64,macos-arm64,ios"
fi

IFS=',' read -r -a TARGET_OSES <<< "$TARGET_OSES"


# shellcheck disable=SC2112
function build_target() {
    local 'target_name' 'target_os' 'build_dir' 'cmake_opt' 'target_arch' 'cached_build_type'

    target_name=$1
    target_os=${2%-*}
    target_arch=${2#*-}
    build_dir=$3

    echo "Building ${target_name} (${target_os})..."

    # A build directory holds one configuration: reconfiguring an existing tree for another
    # build type leaves it broken, so start over when the cached type differs. Same-type runs
    # reuse the tree and rebuild incrementally.
    if [ -f "${build_dir}/CMakeCache.txt" ]; then
        cached_build_type=$(sed -n 's/^CMAKE_BUILD_TYPE:STRING=//p' "${build_dir}/CMakeCache.txt")
        if [ "${cached_build_type}" != "${BUILD_TYPE}" ]; then
            echo "Configuration changed from '${cached_build_type}' to '${BUILD_TYPE}', removing ${build_dir}"
            rm -rf "${build_dir}"
        fi
    fi

    mkdir -pv "${build_dir}"
    cd "${build_dir}"
    pwd

    case ${target_os} in
    ios)
        target_arch=arm64
        ;;
    esac

    target_name=${target_name%-*}
    echo "target_name=${target_name}"
    echo "target_os=${target_os}"

    cmake_opt="-DCMAKE_BUILD_TYPE=${BUILD_TYPE} -GNinja"
    cmake_opt="${cmake_opt} -DCMAKE_XCODE_ATTRIBUTE_DEBUG_INFORMATION_FORMAT=\"dwarf-with-dsym\""
    cmake_opt="${cmake_opt} -DCMAKE_CXX_FLAGS=\"-stdlib=libc++\""
    cmake_opt="${cmake_opt} -DTARGET_OS:STRING=${target_os} -DCMAKE_OSX_ARCHITECTURES=${target_arch}"
    cmake_opt="${cmake_opt} ${EXTRA_CMAKE_ARGS}"

    case ${target_os} in
    ios)
        cmake_opt="${cmake_opt} -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT=iphoneos"
        ;;
    iphonesimulator)
        cmake_opt="${cmake_opt} -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT=iphonesimulator"
        ;;
    esac

    cmake ${cmake_opt} "${FRAMEWORK_DIR}"
    if [ $? != 0 ]; then
        echo "CMake error!"
        exit 1
    fi

    ninja -v ${target_name}
    if [ $? != 0 ]; then
        echo "make error!"
        exit 1
    fi

    if [ -n "${CODESIGN_IDENTITY}" ]; then
        codesign --force --sign "${CODESIGN_IDENTITY}" --options runtime --timestamp "${target_name}.framework"
    fi

    cd -

    echo "${target_name} (${target_os}) has been built successfully"
}


for i in "${!TARGET_OSES[@]}"; do
    target=${TARGET_OSES[$i]}
    echo "Building target: ${target}"
    build_target "${TARGET_NAME}" "${target}" "${BUILD_DIR}/framework-${target}"
done


echo "Making XCFramework..."

# The assembled output is rebuilt from scratch: the copy below merges into a directory and
# -create-xcframework refuses to overwrite an existing framework. The per-platform build
# directories are reused as-is.
rm -rf "${BUILD_DIR}/framework"
mkdir -p "${BUILD_DIR}/framework"

# Only the platforms requested through TARGET_OSES are assembled, so a macOS-only build
# does not fail on the iOS slices that were not built.
has_platform() {
    local prefix=$1
    local target
    for target in "${TARGET_OSES[@]}"; do
        case "${target}" in
        ${prefix}*) return 0 ;;
        esac
    done
    return 1
}

# compose_platform_framework <output dir> <binary path inside the .framework> <sources...>
compose_platform_framework() {
    local out_dir=$1
    local binary=$2
    shift 2

    local sources=()
    local source
    for source in "$@"; do
        if [ -d "${source}" ]; then
            sources+=("${source}")
        fi
    done
    if [ ${#sources[@]} -eq 0 ]; then
        echo "No sources for ${out_dir}" >&2
        exit 1
    fi

    rm -rf "${out_dir}"
    mkdir -p "${out_dir}"
    cp -Rf "${sources[0]}/${TARGET_NAME}.framework" "${out_dir}/"
    rm "${out_dir}/${TARGET_NAME}.framework/${binary}"

    local inputs=("${out_dir}/${TARGET_NAME}.framework/${binary}")
    for source in "${sources[@]}"; do
        inputs+=("${source}/${TARGET_NAME}.framework/${binary}")
    done
    lipo -create -output "${inputs[0]}" "${inputs[@]}"
}

if has_platform "macos-"; then
    compose_platform_framework "${BUILD_DIR}/framework-macos" "Versions/A/${TARGET_NAME}" \
        "${BUILD_DIR}/framework-macos-x86_64" "${BUILD_DIR}/framework-macos-arm64"
fi

if has_platform "iphonesimulator-"; then
    compose_platform_framework "${BUILD_DIR}/framework-iphonesimulator" "${TARGET_NAME}" \
        "${BUILD_DIR}/framework-iphonesimulator-x86_64" "${BUILD_DIR}/framework-iphonesimulator-arm64"
fi

xcframework_args=()
if has_platform "ios"; then
    dsymutil -o "${BUILD_DIR}/framework-ios/${TARGET_NAME}.framework.dSYM" "${BUILD_DIR}/framework-ios/${TARGET_NAME}.framework/${TARGET_NAME}"
    xcframework_args+=(-framework "${BUILD_DIR}/framework-ios/${TARGET_NAME}.framework")
    xcframework_args+=(-debug-symbols "${BUILD_DIR}/framework-ios/${TARGET_NAME}.framework.dSYM")
fi
if has_platform "iphonesimulator-"; then
    dsymutil -o "${BUILD_DIR}/framework-iphonesimulator/${TARGET_NAME}.framework.dSYM" "${BUILD_DIR}/framework-iphonesimulator/${TARGET_NAME}.framework/${TARGET_NAME}"
    xcframework_args+=(-framework "${BUILD_DIR}/framework-iphonesimulator/${TARGET_NAME}.framework")
    xcframework_args+=(-debug-symbols "${BUILD_DIR}/framework-iphonesimulator/${TARGET_NAME}.framework.dSYM")
fi
if has_platform "macos-"; then
    dsymutil -o "${BUILD_DIR}/framework-macos/${TARGET_NAME}.framework.dSYM" "${BUILD_DIR}/framework-macos/${TARGET_NAME}.framework/${TARGET_NAME}"
    xcframework_args+=(-framework "${BUILD_DIR}/framework-macos/${TARGET_NAME}.framework")
    xcframework_args+=(-debug-symbols "${BUILD_DIR}/framework-macos/${TARGET_NAME}.framework.dSYM")
fi

xcodebuild -create-xcframework "${xcframework_args[@]}" \
            -output "${BUILD_DIR}/framework/${TARGET_NAME}.xcframework"

echo "XCFramework has been made successfully"
