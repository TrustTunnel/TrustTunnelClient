# Builds are driven by the CMake presets in CMakePresets.json. The active
# preset is selected from COMPILER (clang/msvc) and BUILD_TYPE (release/debug),
# but PRESET can be set directly to use any preset, e.g.
#   make PRESET=clang-debug-sanitizer test
#   make PRESET=musl-cross-mips-relwithdebinfo build_and_export_bin
BUILD_TYPE ?= release

ifeq ($(OS), Windows_NT)
COMPILER ?= msvc
else
COMPILER ?= clang
endif

ifeq ($(BUILD_TYPE), release)
PRESET ?= $(COMPILER)-relwithdebinfo
else
PRESET ?= $(COMPILER)-debug
endif

# Each preset configures into ${sourceDir}/cmake-build-${presetName}. Override
# BUILD_DIR to configure the same preset into several directories, e.g. when
# building one architecture per directory for a macOS universal binary.
BUILD_DIR ?= cmake-build-$(PRESET)
COMPILE_COMMANDS = $(BUILD_DIR)/compile_commands.json
EXPORT_DIR ?= bin
SETUP_WIZARD_DIR = trusttunnel/setup_wizard

ifeq ($(OS), Windows_NT)
EXE_SUFFIX = .exe
NPROC ?= $(or $(NUMBER_OF_PROCESSORS),8)
else
NPROC ?= $(shell (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8) | tr -d '\n')
UNAME_S := $(shell uname -s)
endif

# Conan regenerates CMakeUserPresets.json on every configure, adding one
# include per build directory. Two build directories with the same build type
# yield two presets named `conan-<build type>`, and CMake refuses to read a
# preset file with duplicates. The file is generated, so drop it beforehand.
CONAN_USER_PRESETS = CMakeUserPresets.json
ifeq ($(OS), Windows_NT)
REMOVE_CONAN_USER_PRESETS = -del /q $(CONAN_USER_PRESETS) 2>nul
else
REMOVE_CONAN_USER_PRESETS = rm -f $(CONAN_USER_PRESETS)
endif

# On macOS CMake would otherwise build for whatever architecture the toolchain
# defaults to, so pin it to the host. Override with ARCH, which also takes a
# semicolon-separated list for a universal binary, e.g.
#   make ARCH=x86_64 test
#   make ARCH='arm64;x86_64' all
# Not applied to the cross-compiling presets, which don't target Apple.
#
# Raise the deployment target to 11.0 once the code starts using
# <stop_token>: libc++ marks it unavailable before macOS 11.
MACOS_DEPLOYMENT_TARGET ?= 10.15
ifeq ($(UNAME_S), Darwin)
ifeq ($(findstring cross,$(PRESET)),)
ARCH ?= $(shell uname -m)
OSX_ARCH_ARGS = -DCMAKE_OSX_ARCHITECTURES="$(ARCH)" \
	-DCMAKE_OSX_DEPLOYMENT_TARGET="$(MACOS_DEPLOYMENT_TARGET)"
endif
endif

.PHONY: help
## Show this help.
help:
	@awk 'BEGIN {FS = ":"} \
		/^## / {doc = doc substr($$0, 4) " "; next} \
		/^\.PHONY/ {next} \
		/^[a-zA-Z0-9_-]+:/ {if (doc != "") {printf "  \033[36m%-28s\033[0m %s\n", $$1, doc}} \
		{doc = ""}' $(MAKEFILE_LIST)

.PHONY: all
## Build all binaries (client + wizard). Default target.
all: build_trusttunnel_client build_wizard

.PHONY: init
## Initialize the development environment (git hooks, etc.)
init:
	git config core.hooksPath ./scripts/hooks

.PHONY: bootstrap_deps
## Export all the required conan packages to the local cache.
## Skips if all dependencies are already resolved in the local Conan cache.
bootstrap_deps:
	@if conan graph info . --profile:host=default >/dev/null 2>&1; then \
		echo "Conan dependencies already bootstrapped, skipping."; \
	else \
		$(MAKE) do_bootstrap_deps; \
	fi

.PHONY: do_bootstrap_deps
ifeq ($(SKIP_VENV),1)
do_bootstrap_deps:
	./scripts/bootstrap_conan_deps.py
else
do_bootstrap_deps:
	python3 -m venv env && \
	. env/bin/activate && \
	pip install -r requirements.txt && \
	./scripts/bootstrap_conan_deps.py
endif

.PHONY: setup_cmake
## Configure the project with the selected CMake preset (resolves Conan deps).
## Extra CMake flags can be passed via CMAKE_ARGS, e.g.
##   make CMAKE_ARGS=-DIPV6_UNAVAILABLE=ON test
## Set SKIP_BOOTSTRAP=1 to skip bootstrapping dependencies.
## Run `make reconfigure` to apply changed CMAKE_ARGS to a configured tree.
setup_cmake: $(BUILD_DIR)/CMakeCache.txt

# Configure only when the build directory has no cache yet. Re-running
# `cmake --preset` over an existing cache breaks the musl cross presets: their
# compiler is a list (`zig;cc;-target;...`), which CMake stores split into
# CMAKE_C_COMPILER plus CMAKE_C_COMPILER_ARG1 and then reports as changed,
# wiping the cache and re-testing `zig` without its arguments. Ninja still
# regenerates by itself when CMakeLists.txt changes.
# bootstrap_deps is order-only: it is phony, and a normal prerequisite would
# make the cache look out of date on every run.
ifeq ($(SKIP_BOOTSTRAP),1)
$(BUILD_DIR)/CMakeCache.txt:
else
$(BUILD_DIR)/CMakeCache.txt: | bootstrap_deps
endif
	$(REMOVE_CONAN_USER_PRESETS)
	cmake --preset $(PRESET) -B $(BUILD_DIR) $(OSX_ARCH_ARGS) $(CMAKE_ARGS)

.PHONY: reconfigure
## Re-run the CMake configure step from scratch, e.g. after changing CMAKE_ARGS.
reconfigure:
	rm -f $(BUILD_DIR)/CMakeCache.txt
	$(MAKE) setup_cmake

.PHONY: compile_commands
## Generate compile_commands.json for IDE / clang-tidy integration.
compile_commands:
	$(REMOVE_CONAN_USER_PRESETS)
	cmake --preset $(PRESET) -B $(BUILD_DIR) $(OSX_ARCH_ARGS) $(CMAKE_ARGS) \
		-DCMAKE_EXPORT_COMPILE_COMMANDS=ON

.PHONY: build_libs
## Build the libraries
build_libs: setup_cmake
	cmake --build $(BUILD_DIR) --target vpnlibs_core -j$(NPROC)

.PHONY: build_trusttunnel_client
## Build the VPN client binary
build_trusttunnel_client: setup_cmake
	cmake --build $(BUILD_DIR) --target trusttunnel_client -j$(NPROC)

.PHONY: build_wizard
## Build the setup wizard binary for the VPN client
build_wizard: setup_cmake
	cmake --build $(BUILD_DIR) --target setup_wizard -j$(NPROC)

.PHONY: build_and_export_bin
## Build and copy all binaries in the specified directory
build_and_export_bin: build_trusttunnel_client build_wizard
	mkdir -p $(EXPORT_DIR)
	cp $(BUILD_DIR)/trusttunnel/trusttunnel_client$(EXE_SUFFIX) \
		$(BUILD_DIR)/trusttunnel/setup_wizard$(EXE_SUFFIX) \
		$(EXPORT_DIR)
	@echo "Binaries are stored in $(EXPORT_DIR)"

.PHONY: clean
## Clean the project
clean:
	cmake --build $(BUILD_DIR) --target clean

.PHONY: lint
## Run all linters (markdown + Rust + C++).
lint: lint-md lint-rust lint-cpp

## Lint c++ files.
.PHONY: lint-cpp
lint-cpp: clang-format clangd-tidy

## Verify that clang-format is version 21 or newer.
.PHONY: check-clang-format-version
check-clang-format-version:
	@if ! command -v clang-format >/dev/null 2>&1; then \
		echo "Error: clang-format is not installed" >&2; exit 1; \
	fi
	@CF_VERSION=$$(clang-format --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1); \
	CF_MAJOR=$$(echo "$$CF_VERSION" | cut -d. -f1); \
	if [ "$$CF_MAJOR" -lt 21 ] 2>/dev/null; then \
		echo "Error: clang-format version 21 or newer is required, found $$CF_VERSION" >&2; exit 1; \
	fi

## Check c++ code formatting with clang-format.
.PHONY: clang-format
clang-format: check-clang-format-version
	git ls-files --exclude-standard -- . ":!third-party/**" ":!**/pigeon/**" \
		| grep -E '\.(cpp|c|h)$$' \
		| xargs clang-format -n -Werror

## Check c++ code formatting with clang-tidy.
.PHONY: clang-tidy
clang-tidy: compile_commands
	run-clang-tidy -p $(BUILD_DIR) -config-file='.clang-tidy' '^(?!.*(/third-party/)).*\.cpp$$'

## Check c++ code formatting with clangd-tidy.
.PHONY: clangd-tidy
clangd-tidy: compile_commands
ifeq ($(SKIP_VENV),1)
	jq -r '.[] | select(.file | endswith(".cpp")) | .file' $(COMPILE_COMMANDS) \
		| grep -vE '(^|/)(third-party)(/|$$)' \
		| sort -u \
		| xargs clangd-tidy -p $(BUILD_DIR) --tqdm -j$(NPROC)
else
	python3 -m venv env && \
	. env/bin/activate && \
	pip install -r requirements.txt && \
	jq -r '.[] | select(.file | endswith(".cpp")) | .file' $(COMPILE_COMMANDS) \
		| grep -vE '(^|/)(third-party)(/|$$)' \
		| sort -u \
		| xargs clangd-tidy -p $(BUILD_DIR) --tqdm -j$(NPROC)
endif

## Lint markdown files.
## `markdownlint-cli` should be installed:
##    macOS: `brew install markdownlint-cli`
##    Linux: `npm install -g markdownlint-cli`
.PHONY: lint-md
lint-md:
	echo markdownlint version:
	markdownlint --version
	markdownlint .

## Check Rust code formatting with rustfmt.
## `rustfmt` should be installed:
##    rustup component add rustfmt
.PHONY: lint-rust
lint-rust:
	cargo clippy --manifest-path $(SETUP_WIZARD_DIR)/Cargo.toml -- -D warnings
	cargo fmt --all --manifest-path $(SETUP_WIZARD_DIR)/Cargo.toml -- --check

## Fix linter issues that are auto-fixable.
.PHONY: lint-fix
lint-fix: lint-fix-rust lint-fix-md lint-fix-cpp

## Auto-fix c++ formatting with clang-format.
.PHONY: lint-fix-cpp
lint-fix-cpp: check-clang-format-version
	git ls-files --exclude-standard -- . ":!third-party/**" ":!**/pigeon/**" \
		| grep -E '\.(cpp|c|h)$$' \
		| xargs clang-format -i

## Auto-fix Rust code formatting issues with rustfmt.
.PHONY: lint-fix-rust
lint-fix-rust:
	cargo clippy --fix --allow-dirty --manifest-path $(SETUP_WIZARD_DIR)/Cargo.toml
	cargo fmt --all --manifest-path $(SETUP_WIZARD_DIR)/Cargo.toml

## Auto-fix markdown files.
.PHONY: lint-fix-md
lint-fix-md:
	markdownlint --fix .

## List Conan dependency package directories.
.PHONY: list-deps-dirs
list-deps-dirs: compile_commands
	@GENERATORS_DIR=$$(cmake -L $(BUILD_DIR) 2>/dev/null \
		| grep '_DIR:PATH=' \
		| grep -v 'NOTFOUND' \
		| head -1 \
		| sed 's/.*:PATH=//') && \
	grep -h '_PACKAGE_FOLDER_' "$$GENERATORS_DIR"/* 2>/dev/null \
		| sed -n 's/set(\(.*\)_PACKAGE_FOLDER_[A-Z_]* "\([^"]*\)").*/\1 \2/p' \
		| sort -u

.PHONY: test
## Run all unit tests (C++ + Rust).
test: test-cpp test-rust

.PHONY: build_tests
## Build the C++ unit test executables.
build_tests: build_libs
	cmake --build $(BUILD_DIR) --target tests -j$(NPROC)

.PHONY: test-cpp
## Build and run the C++ unit tests via CTest.
## A JUnit report is written to $(BUILD_DIR)/junit.xml for CI consumption;
## extra CTest flags can be passed via CTEST_ARGS.
test-cpp: build_tests
	ctest --test-dir $(BUILD_DIR) --output-junit junit.xml \
		--no-compress-output --output-on-failure $(CTEST_ARGS)

.PHONY: build_live_tests
## Build the live (network-dependent) test executables.
build_live_tests: setup_cmake
	cmake --build $(BUILD_DIR) --target live_tests -j$(NPROC)

.PHONY: test-live
## Build and run the live tests. Requires network access and
## -DVPNLIBS_ENABLE_LIVE_TESTS=ON, e.g.
##   make CMAKE_ARGS=-DVPNLIBS_ENABLE_LIVE_TESTS=ON test-live
## test_vpn_client_live is excluded: it needs a running endpoint and is driven
## by the integration test pipeline instead.
test-live: build_live_tests
	ctest --test-dir $(BUILD_DIR) --output-junit junit.xml \
		--output-on-failure -L live -E test_vpn_client_live

.PHONY: test-rust
## Run the Rust unit tests of the setup wizard workspace.
test-rust:
	cargo test --workspace --manifest-path $(SETUP_WIZARD_DIR)/Cargo.toml
