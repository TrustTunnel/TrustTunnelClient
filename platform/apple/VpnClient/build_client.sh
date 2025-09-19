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

TARGET_OSES="all"
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
    local 'target_name' 'target_os' 'build_dir' 'cmake_opt' 'target_arch'

    target_name=$1
    target_os=${2%-*}
    target_arch=${2#*-}
    build_dir=$3

    echo "Building ${target_name} (${target_os})..."

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

rm -rf "${BUILD_DIR}/${TARGET_NAME}.xcframework"
rm -rf "${BUILD_DIR}/${TARGET_NAME}.dSYMs"
rm -rf "${BUILD_DIR}/framework-macos"
rm -rf "${BUILD_DIR}/framework-iphonesimulator"
rm -rf "${BUILD_DIR}/framework"

mkdir -p "${BUILD_DIR}/framework-macos"
cp -Rf "${BUILD_DIR}/framework-macos-x86_64/${TARGET_NAME}.framework" "${BUILD_DIR}/framework-macos/"
rm "${BUILD_DIR}/framework-macos/${TARGET_NAME}.framework/Versions/A/${TARGET_NAME}"
lipo -create -output "${BUILD_DIR}"/framework-macos{,-x86_64,-arm64}/"${TARGET_NAME}.framework/Versions/A/${TARGET_NAME}"
mkdir -p "${BUILD_DIR}/framework-iphonesimulator"
cp -Rf "${BUILD_DIR}/framework-iphonesimulator-x86_64/${TARGET_NAME}.framework" "${BUILD_DIR}/framework-iphonesimulator/"
rm "${BUILD_DIR}/framework-iphonesimulator/${TARGET_NAME}.framework/${TARGET_NAME}"
lipo -create -output "${BUILD_DIR}"/framework-iphonesimulator{,-x86_64,-arm64}/"${TARGET_NAME}.framework/${TARGET_NAME}"

dsymutil -o "${BUILD_DIR}/framework-ios/${TARGET_NAME}.framework.dSYM" "${BUILD_DIR}/framework-ios/${TARGET_NAME}.framework/${TARGET_NAME}"
dsymutil -o "${BUILD_DIR}/framework-iphonesimulator/${TARGET_NAME}.framework.dSYM" "${BUILD_DIR}/framework-iphonesimulator/${TARGET_NAME}.framework/${TARGET_NAME}"
dsymutil -o "${BUILD_DIR}/framework-macos/${TARGET_NAME}.framework.dSYM" "${BUILD_DIR}/framework-macos/${TARGET_NAME}.framework/${TARGET_NAME}"
xcodebuild -create-xcframework \
            -framework ${BUILD_DIR}/framework-ios/${TARGET_NAME}.framework \
            -debug-symbols "${BUILD_DIR}/framework-ios/${TARGET_NAME}.framework.dSYM" \
            -framework ${BUILD_DIR}/framework-iphonesimulator/${TARGET_NAME}.framework \
            -debug-symbols "${BUILD_DIR}/framework-iphonesimulator/${TARGET_NAME}.framework.dSYM" \
            -framework ${BUILD_DIR}/framework-macos/${TARGET_NAME}.framework \
            -debug-symbols "${BUILD_DIR}/framework-macos/${TARGET_NAME}.framework.dSYM" \
            -output "${BUILD_DIR}/framework/${TARGET_NAME}.xcframework"

echo "XCFramework has been made successfully"
