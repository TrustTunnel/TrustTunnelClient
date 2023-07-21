from conans import ConanFile, CMake, tools
import os


class VpnLibsConan(ConanFile):
    name = "vpn-libs"
    license = "GPL-3.0-or-later"
    author = "AdguardTeam"
    url = "https://github.com/AdguardTeam/VpnLibs"
    vcs_url = "https://github.com/AdguardTeam/VpnLibs.git"
    description = "A VPN client library that provides client network traffic tunnelling to an AdGuard VPN server"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "commit_hash": "ANY",
        "sanitize": "ANY"
    }
    default_options = {
        "commit_hash": None,  # None means `master`
        "sanitize": None,  # None means none
    }
    generators = "cmake"
    # A list of paths to patches. The paths must be relative to the conanfile directory.
    # They are applied in case of the version equals 777 and mostly intended to be used
    # for testing.
    patch_files = []
    exports_sources = patch_files

    def requirements(self):
        self.requires("brotli/1.0.9")
        self.requires("dns-libs/2.2.13@AdguardTeam/NativeLibsCommon")
        self.requires("http_parser/2.9.4")
        self.requires("klib/2021-04-06@AdguardTeam/NativeLibsCommon")
        self.requires("ldns/2021-03-29@AdguardTeam/NativeLibsCommon")
        self.requires("libevent/2.1.11@AdguardTeam/NativeLibsCommon")
        self.requires("magic_enum/0.7.3")
        self.requires("native_libs_common/2.0.60@AdguardTeam/NativeLibsCommon")
        self.requires("nghttp2/1.44.0@AdguardTeam/NativeLibsCommon")
        self.requires("openssl/boring-2021-05-11@AdguardTeam/NativeLibsCommon")
        self.requires("quiche/0.17.1@AdguardTeam/NativeLibsCommon")
        self.requires("zlib/1.2.11")

        if tools.is_apple_os(self.settings.os):
            self.requires("ghc-filesystem/1.5.12")

    def build_requirements(self):
        self.build_requires("cxxopts/3.0.0")
        self.build_requires("gtest/1.12.1")
        self.build_requires("nlohmann_json/3.10.5")
        self.build_requires("tomlplusplus/3.3.0")

    def configure(self):
        self.options["gtest"].build_gmock = False
        # Commit hash should only be used with dns-libs/777
        # self.options["dns-libs"].commit_hash = "0a218d35f64e91bd8621bad94c8ca473f3f9fd31"

        # Resolve conflict between pcre2 required from dns-libs and pcre2 required form native_libs_common
        self.options["pcre2"].build_pcre2grep = False

        # Commit hash should only be used with native_libs_common/777
        # self.options["native_libs_common"].commit_hash = "72731a36771d550ffae8c1223e0a129fefc2384c"

    def source(self):
        self.run(f"git init . && git remote add origin {self.vcs_url} && git fetch")

        if self.version == "777":
            if self.options.commit_hash:
                self.run("git checkout -f %s" % self.options.commit_hash)
            else:
                self.run("git checkout -f master")

            for p in self.patch_files:
                tools.patch(patch_file=p)
        else:
            version_hash = self.conan_data["commit_hash"][self.version]["hash"]
            self.run("git checkout -f %s" % version_hash)

    def build(self):
        cmake = CMake(self)
        cmake.definitions["CMAKE_C_FLAGS"] = ""
        cmake.definitions["CMAKE_CXX_FLAGS"] = ""
        # A better way to pass these was not found :(
        if self.settings.os == "Linux":
            if self.settings.compiler.libcxx:
                cmake.definitions["CMAKE_CXX_FLAGS"] = "-stdlib=%s" % self.settings.compiler.libcxx
            if self.settings.compiler.version:
                cmake.definitions["CMAKE_CXX_COMPILER_VERSION"] = self.settings.compiler.version
        if self.options.sanitize:
            cmake.definitions["CMAKE_C_FLAGS"] += f" -fno-omit-frame-pointer -fsanitize={self.options.sanitize}"
            cmake.definitions["CMAKE_CXX_FLAGS"] += f" -fno-omit-frame-pointer -fsanitize={self.options.sanitize}"
        cmake.configure(source_folder=".", build_folder="build")
        cmake.build(target="vpnlibs_common")
        cmake.build(target="vpnlibs_core")
        cmake.build(target="vpnlibs_net")
        cmake.build(target="vpnlibs_tcpip")

    def package(self):
        MODULES = [
            "common",
            "core",
            "net",
            "tcpip",
        ]

        for m in MODULES:
            self.copy("*.h", dst="include", src="%s/include" % m)

        self.copy("*.h", dst="include", src=os.path.join("third-party", "wintun", "include"))

        self.copy("*.lib", dst="lib", keep_path=False)
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = [
            "vpnlibs_core",
            "vpnlibs_net",
            "vpnlibs_tcpip",
            "vpnlibs_common",
        ]

        if self.settings.os == "Windows":
            self.cpp_info.system_libs = ["Version"]
        elif self.settings.os != 'Android':
            self.cpp_info.system_libs = ["resolv"]
