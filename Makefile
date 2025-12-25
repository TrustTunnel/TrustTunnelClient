BUILD_TYPE ?= release
ifeq ($(BUILD_TYPE), release)
	CMAKE_BUILD_TYPE = RelWithDebInfo
else
	CMAKE_BUILD_TYPE = Debug
endif
MSVC_VER ?= 17
ifeq ($(origin MSVC_YEAR), undefined)
	ifeq ($(MSVC_VER), 16)
		MSVC_YEAR = 2019
	else ifeq ($(MSVC_VER), 17)
		MSVC_YEAR = 2022
	endif
endif
BUILD_DIR = build
EXPORT_DIR ?= bin
SETUP_WIZARD_DIR = trusttunnel/setup_wizard

.PHONY: init
## Initialize the development environment (git hooks, etc.)
init:
	git config core.hooksPath ./scripts/hooks

.PHONY: bootstrap_deps
## Export all the required conan packages to the local cache
bootstrap_deps:
	python3 -m venv env && \
	. env/bin/activate && \
	pip install -r requirements.txt && \
	./scripts/bootstrap_conan_deps.py

.PHONY: setup_cmake
## Setup CMake
setup_cmake: bootstrap_deps
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
	-GNinja \
	..
endif
# Prepare compile_commands.json
cmake -S . -B $(BUILD_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

.PHONY: build_libs
## Build the libraries
build_libs: setup_cmake
	cmake --build $(BUILD_DIR) --target vpnlibs_core

.PHONY: build_trusttunnel_client
## Build the VPN client binary
build_trusttunnel_client: build_libs
	cmake --build $(BUILD_DIR) --target trusttunnel_client

.PHONY: build_wizard
## Build the setup wizard binary for the VPN client
build_wizard:
	cmake --build $(BUILD_DIR) --target setup_wizard
.PHONY: all
## Build all binaries
all: build_trusttunnel_client build_wizard

.PHONY: build_and_export_bin
## Build and copy all binaries in the specified directory
build_and_export_bin: build_trusttunnel_client build_wizard
	mkdir -p $(EXPORT_DIR)
	cp $(BUILD_DIR)/trusttunnel/trusttunnel_client \
		$(BUILD_DIR)/trusttunnel/setup_wizard \
		$(EXPORT_DIR)
	@echo "Binaries are stored in $(EXPORT_DIR)"

.PHONY: clean
## Clean the project
clean:
	cmake --build $(BUILD_DIR) --target clean

.PHONY: lint
lint: lint-md lint-rust lint-cpp

## Lint c++ files.
## TODO: enable clang-tidy
.PHONY: lint-cpp
lint-cpp: clang-format

## Check c++ code formatting with clang-format.
.PHONY: clang-format
clang-format:
	find . \
	-path './third-party' -prune -o \
	-name '*.c' -o -name '*.cpp' -o -name '*.h' \
	-print | xargs clang-format -n -Werror

## Check c++ code formatting with clang-tidy.
.PHONY: clang-tidy
clang-tidy: setup_cmake
	run-clang-tidy -p $(BUILD_DIR) '^(?!.*(/third-party/)).*\.cpp$$'

## Lint markdown files.
## `markdownlint-cli` should be installed:
##    macOS: `brew install markdownlint-cli`
##    Linux: `npm install -g markdownlint-cli`
.PHONY: lint-md
lint-md:
	markdownlint .

## Check Rust code formatting with rustfmt.
## `rustfmt` should be installed:
##    rustup component add rustfmt
.PHONY: lint-rust
lint-rust:
	cargo fmt --all --manifest-path $(SETUP_WIZARD_DIR)/Cargo.toml -- --check

## Fix linter issues that are auto-fixable.
.PHONY: lint-fix
lint-fix: lint-fix-rust lint-fix-md lint-fix-cpp

## Auto-fix c++ formatting with clang-format.
.PHONY: lint-fix-cpp
lint-fix-cpp:
	find . \
		-path './third-party' -prune -o \
		-name '*.c' -o -name '*.cpp' -o -name '*.h' \
		-print | xargs clang-format -i

## Auto-fix Rust code formatting issues with rustfmt.
.PHONY: lint-fix-rust
lint-fix-rust:
	cargo fmt --all --manifest-path $(SETUP_WIZARD_DIR)/Cargo.toml

## Auto-fix markdown files.
.PHONY: lint-fix-md
lint-fix-md:
	markdownlint --fix .

.PHONY: test
test: test-cpp test-rust

.PHONY: test-cpp
test-cpp: build_libs
	cmake --build $(BUILD_DIR) --target tests
	ctest --test-dir $(BUILD_DIR)

.PHONY: test-rust
test-rust:
	cargo test --workspace --manifest-path $(SETUP_WIZARD_DIR)/Cargo.toml