from conans import ConanFile, CMake, tools
import os


class VpnLibsConan(ConanFile):
    name = "vpn-libs"
    license = "GPL-3.0-or-later"
    author = "AdguardTeam"
    url = "https://github.com/AdguardTeam/VpnLibs"
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

    def requirements(self):
        for req in self.conan_data["requirements"]:
            self.requires(req)

        if tools.is_apple_os(self.settings.os):
            for req in self.conan_data["requirements_apple"]:
                self.requires(req)

    def build_requirements(self):
        self.build_requires("gtest/1.12.1")
        self.build_requires("cxxopts/3.0.0")
        self.build_requires("nlohmann_json/3.10.5")

    def configure(self):
        self.options["gtest"].build_gmock = False
        # 2.0.34
        self.options["dns-libs"].commit_hash = "f1d8cabea8fff416d4ed23ebfd58207e66698ae9"

        # Resolve conflict between pcre2 required from dns-libs and pcre2 required form native_libs_common
        self.options["pcre2"].build_pcre2grep = False

        # Commit hash should only be used with native_libs_common/777
        # self.options["native_libs_common"].commit_hash = "72731a36771d550ffae8c1223e0a129fefc2384c"

    def source(self):
        self.run("git init . && git remote add origin https://github.com/AdguardTeam/VpnLibs.git && git fetch")

        if self.version == "777":
            if self.options.commit_hash:
                self.run("git checkout -f %s" % self.options.commit_hash)
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
