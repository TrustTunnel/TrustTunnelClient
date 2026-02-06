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
COMPILE_COMMANDS = $(BUILD_DIR)/compile_commands.json
EXPORT_DIR ?= bin
SETUP_WIZARD_DIR = trusttunnel/setup_wizard

# Common CMake flags
ifeq ($(OS), Windows_NT)
CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=RelWithDebInfo \
	-DCMAKE_C_COMPILER="cl.exe" \
	-DCMAKE_CXX_COMPILER="cl.exe" \
	-G "Ninja"
else
CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) \
	-DCMAKE_C_COMPILER="clang" \
	-DCMAKE_CXX_COMPILER="clang++" \
	-DCMAKE_CXX_FLAGS="-stdlib=libc++" \
	-GNinja
endif

.PHONY: init
## Initialize the development environment (git hooks, etc.)
init:
	git config core.hooksPath ./scripts/hooks

.PHONY: bootstrap_deps
## Export all the required conan packages to the local cache
bootstrap_deps:
ifeq ($(SKIP_VENV),1)
	./scripts/bootstrap_conan_deps.py
else
	python3 -m venv env && \
	. env/bin/activate && \
	pip install -r requirements.txt && \
	./scripts/bootstrap_conan_deps.py
endif

.PHONY: setup_cmake
## Setup CMake
## Set SKIP_BOOTSTRAP=1 to skip bootstrapping dependencies
ifeq ($(SKIP_BOOTSTRAP),1)
setup_cmake:
else
setup_cmake: bootstrap_deps
endif
	mkdir -p $(BUILD_DIR) && cmake -S . -B $(BUILD_DIR) $(CMAKE_FLAGS)

.PHONY: compile_commands
## Generate compile_commands.json
compile_commands:
	mkdir -p $(BUILD_DIR) && cmake -S . -B $(BUILD_DIR) \
		$(CMAKE_FLAGS) \
		-DCMAKE_EXPORT_COMPILE_COMMANDS=ON

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
.PHONY: lint-cpp
lint-cpp: clang-format clangd-tidy

## Check c++ code formatting with clang-format.
.PHONY: clang-format
clang-format:
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
	jq -r '.[] | select(.file | endswith(".cpp")) | .file' $(COMPILE_COMMANDS) \
		| grep -vE '(^|/)(third-party)(/|$$)' \
		| sort -u \
		| xargs clangd-tidy -p $(BUILD_DIR)

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
lint-fix-cpp:
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

.PHONY: test
test: test-cpp test-rust

.PHONY: test-cpp
test-cpp: build_libs
	cmake --build $(BUILD_DIR) --target tests
	ctest --test-dir $(BUILD_DIR)

.PHONY: test-rust
test-rust:
	cargo test --workspace --manifest-path $(SETUP_WIZARD_DIR)/Cargo.toml