BUILD_TYPE ?= release
ifeq ($(BUILD_TYPE), release)
	CMAKE_BUILD_TYPE = RelWithDebInfo
else
	CMAKE_BUILD_TYPE = Debug
endif
MSVC_VER ?= 16
ifeq ($(origin MSVC_YEAR), undefined)
	ifeq ($(MSVC_VER), 16)
		MSVC_YEAR = 2019
	else ifeq ($(MSVC_VER), 17)
		MSVC_YEAR = 2022
	endif
endif
BUILD_DIR = build
EXPORT_DIR ?= bin

.PHONY: bootstrap_deps
## Export all the required conan packages to the local cache
bootstrap_deps:
	./scripts/bootstrap_conan_deps.py conandata.yml \
		https://github.com/AdguardTeam/NativeLibsCommon.git \
		https://github.com/AdguardTeam/DnsLibs.git

.PHONY: build_libs
## Build the libraries
build_libs: bootstrap_deps
ifeq ($(OS), Windows_NT)
	cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
		-DCMAKE_C_FLAGS_DEBUG=/MT ^
		-DCMAKE_CXX_FLAGS_DEBUG=/MT ^
		-G "Visual Studio $(MSVC_VER) $(MSVC_YEAR)" ^
		..
else
	mkdir -p $(BUILD_DIR) && cd $(BUILD_DIR) && \
	cmake -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) \
		-DCMAKE_C_COMPILER="clang" \
		-DCMAKE_CXX_COMPILER="clang++" \
		-DCMAKE_CXX_FLAGS="-stdlib=libc++" \
		..
endif
	cmake --build $(BUILD_DIR) --target vpnlibs_core

.PHONY: build_standalone_client
## Build the VPN client binary
build_standalone_client: build_libs
	cmake --build $(BUILD_DIR) --target standalone_client

.PHONY: build_wizard
## Build the setup wizard binary for the VPN client
build_wizard:
	cmake --build $(BUILD_DIR) --target setup_wizard

.PHONY: all
## Build all binaries
all: build_standalone_client build_wizard

.PHONY: build_and_export_bin
## Build and copy all binaries in the specified directory
build_and_export_bin: build_standalone_client build_wizard
	mkdir -p $(EXPORT_DIR)
	cp $(BUILD_DIR)/standalone_client/standalone_client \
		$(BUILD_DIR)/standalone_client/setup_wizard \
		$(EXPORT_DIR)
	@echo "Binaries are stored in $(EXPORT_DIR)"

.PHONY: clean
## Clean the project
clean:
	cmake --build $(BUILD_DIR) --target clean
