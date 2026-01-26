from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import patch, copy
from conan.tools.apple import is_apple_os
from os.path import join
import re


class VpnLibsConan(ConanFile):
    name = "vpn-libs"
    license = "Apache-2.0"
    author = "TrustTunnel"
    url = "https://github.com/TrustTunnel/TrustTunnelClient"
    vcs_url = "https://github.com/TrustTunnel/TrustTunnelClient.git"
    description = "TrustTunnel client implementation"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "with_ghc": [True, False],
        "sanitize": [None, "ANY"],
    }
    default_options = {
        "with_ghc": False,
        "sanitize": None,  # None means none
    }
    # A list of paths to patches. The paths must be relative to the conanfile directory.
    # They are applied in case of the version equals 777 and mostly intended to be used
    # for testing.
    patch_files = []
    exports_sources = patch_files

    def requirements(self):
        self.requires("dns-libs/2.8.15@adguard/oss", transitive_headers=True)
        self.requires("native_libs_common/8.0.13@adguard/oss", transitive_headers=True)

        self.requires("brotli/1.1.0", transitive_headers=True)
        self.requires("cxxopts/3.1.1", transitive_headers=True)
        self.requires("http_parser/2.9.4", transitive_headers=True)
        self.requires("klib/2021-04-06@adguard/oss", transitive_headers=True)
        self.requires("ldns/2021-03-29@adguard/oss", transitive_headers=True)
        self.requires("libevent/2.1.11@adguard/oss", transitive_headers=True)
        self.requires("magic_enum/0.9.5", transitive_headers=True)
        self.requires("nghttp2/1.56.0@adguard/oss", transitive_headers=True)
        self.requires("nlohmann_json/3.10.5")
        self.requires("tomlplusplus/3.3.0")
        self.requires("zlib/1.3.1", transitive_headers=True)

        if "mips" not in str(self.settings.arch):
            self.requires("quiche/0.17.1@adguard/oss", transitive_headers=True)
            self.requires("openssl/boring-2024-09-13@adguard/oss", transitive_headers=True, force=True)
        else:
            self.requires("openssl/3.1.5-quic1@adguard/oss", transitive_headers=True, force=True)

    def build_requirements(self):
        self.test_requires("gtest/1.14.0")
        self.test_requires("fmt/12.1.0")

    def configure(self):
        self.options["gtest"].build_gmock = False
        # Resolve conflict between pcre2 required from dns-libs and pcre2 required form native_libs_common
        self.options["pcre2"].build_pcre2grep = False

    def source(self):
        self.run(f"git init . && git remote add origin {self.vcs_url} && git fetch")
        if re.match(r'\d+\.\d+\.\d+', self.version) is not None:
            version_hash = self.conan_data["commit_hash"][self.version]["hash"]
            self.run("git checkout -f %s" % version_hash)
        else:
            self.run("git checkout -f %s" % self.version)
            for p in self.patch_files:
                patch(self, patch_file=p)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        if self.options.sanitize:
            tc.cache_variables["CMAKE_C_FLAGS"] += f" -fno-omit-frame-pointer -fsanitize={self.options.sanitize}"
            tc.cache_variables["CMAKE_CXX_FLAGS"] += f" -fno-omit-frame-pointer -fsanitize={self.options.sanitize}"
        tc.generate()

    def layout(self):
        cmake_layout(self)

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build(target="vpnlibs_common")
        cmake.build(target="vpnlibs_core")
        cmake.build(target="vpnlibs_net")
        cmake.build(target="vpnlibs_tcpip")
        cmake.build(target="vpnlibs_trusttunnel")

    def package(self):
        MODULES = [
            "common",
            "core",
            "net",
            "tcpip",
            "trusttunnel",
        ]

        for m in MODULES:
            copy(self, "*.h", src=join(self.source_folder, "%s/include" % m), dst=join(self.package_folder, "include"), keep_path = True)

        copy(self, "*.h", src=join(self.source_folder, "third-party", "wintun", "include"), dst=join(self.package_folder, "include"), keep_path = True)

        copy(self, "*.dll", src=self.build_folder, dst=join(self.package_folder, "bin"), keep_path=False)
        copy(self, "*.lib", src=self.build_folder, dst=join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.so", src=self.build_folder, dst=join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.dylib", src=self.build_folder, dst=join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.a", src=self.build_folder, dst=join(self.package_folder, "lib"), keep_path=False)


    def package_info(self):
        self.cpp_info.name = "vpn-libs"
        self.cpp_info.libs = [
            "vpnlibs_core",
            "vpnlibs_net",
            "vpnlibs_tcpip",
            "vpnlibs_common",
            "vpnlibs_trusttunnel",
        ]
        if self.settings.os == "Windows":
            self.cpp_info.system_libs = ["ws2_32", "crypt32", "userenv", "version", "Fwpuclnt"]
        elif self.settings.os != 'Android':
            self.cpp_info.system_libs = ["resolv"]
        if is_apple_os(self):
            self.cpp_info.frameworks = ['Foundation', 'SystemConfiguration', 'Security']
