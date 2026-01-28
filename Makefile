# Sindarin SDK - Makefile (CMake Wrapper)
#
# This Makefile provides familiar Make targets that delegate to CMake.
# For advanced usage, use CMake directly with presets:
#   cmake --preset linux-gcc-release
#   cmake --build --preset linux-gcc-release
#
# See CMakePresets.json for all available presets.

#------------------------------------------------------------------------------
# Phony targets
#------------------------------------------------------------------------------
.PHONY: all build rebuild clean help
.PHONY: configure install
.PHONY: setup

#------------------------------------------------------------------------------
# Platform Detection
#------------------------------------------------------------------------------
ifeq ($(OS),Windows_NT)
    PLATFORM := windows
    CMAKE_PRESET := windows-clang-release
    CMAKE_DEBUG_PRESET := windows-clang-debug
    EXE_EXT := .exe
    PYTHON := python
    # Always use Ninja on Windows (it's required for this project)
    CMAKE_GENERATOR := Ninja
    TEMP_DIR := $(if $(TEMP),$(TEMP),/tmp)
    MKDIR := cmake -E make_directory
else
    UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
    ifneq ($(filter MINGW% MSYS% CYGWIN%,$(UNAME_S)),)
        PLATFORM := windows
        CMAKE_PRESET := windows-clang-release
        CMAKE_DEBUG_PRESET := windows-clang-debug
        EXE_EXT := .exe
        PYTHON := python
        # MSYS/MinGW uses Unix commands
        RM := rm -f
        RMDIR := rm -rf $(BUILD_DIR)
        MKDIR := mkdir -p
        NULL_DEV := /dev/null
        NINJA_EXISTS := $(shell command -v ninja >/dev/null 2>&1 && echo yes || echo no)
        CMAKE_GENERATOR := $(if $(filter yes,$(NINJA_EXISTS)),Ninja,Unix Makefiles)
        TEMP_DIR := /tmp
    else ifeq ($(UNAME_S),Darwin)
        PLATFORM := darwin
        CMAKE_PRESET := macos-clang-release
        CMAKE_DEBUG_PRESET := macos-clang-debug
        EXE_EXT :=
        PYTHON := python3
        # Unix commands
        RM := rm -f
        RMDIR := rm -rf $(BUILD_DIR)
        MKDIR := mkdir -p
        NULL_DEV := /dev/null
        NINJA_EXISTS := $(shell command -v ninja >/dev/null 2>&1 && echo yes || echo no)
        CMAKE_GENERATOR := $(if $(filter yes,$(NINJA_EXISTS)),Ninja,Unix Makefiles)
        TEMP_DIR := /tmp
    else
        PLATFORM := linux
        CMAKE_PRESET := linux-gcc-release
        CMAKE_DEBUG_PRESET := linux-gcc-debug
        EXE_EXT :=
        PYTHON := python3
        # Unix commands
        RM := rm -f
        RMDIR := rm -rf $(BUILD_DIR)
        MKDIR := mkdir -p
        NULL_DEV := /dev/null
        NINJA_EXISTS := $(shell command -v ninja >/dev/null 2>&1 && echo yes || echo no)
        CMAKE_GENERATOR := $(if $(filter yes,$(NINJA_EXISTS)),Ninja,Unix Makefiles)
        TEMP_DIR := /tmp
    endif
endif

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------
BUILD_DIR := build
DEPS_DIR := deps

# Allow preset override
PRESET ?= $(CMAKE_PRESET)

# Select compiler based on platform
CMAKE_C_COMPILER := $(if $(filter windows,$(PLATFORM)),clang,$(if $(filter darwin,$(PLATFORM)),clang,gcc))

#------------------------------------------------------------------------------
# Default target
#------------------------------------------------------------------------------
all: build

#------------------------------------------------------------------------------
# build - Configure and build (copies dependencies to deps/)
#------------------------------------------------------------------------------
build:
	@echo "Building Sindarin SDK dependencies..."
	@echo "Platform: $(PLATFORM)"
	@echo "Generator: $(CMAKE_GENERATOR)"
	cmake -S . -B $(BUILD_DIR) -G "$(CMAKE_GENERATOR)" \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_COMPILER=$(CMAKE_C_COMPILER)
	cmake --build $(BUILD_DIR)
	@echo ""
	@echo "Build complete!"
	@echo "Dependencies copied to: $(DEPS_DIR)/"

#------------------------------------------------------------------------------
# rebuild - Clean and build
#------------------------------------------------------------------------------
rebuild: clean build

#------------------------------------------------------------------------------
# configure - Just configure CMake (useful for IDE integration)
#------------------------------------------------------------------------------
configure:
	@echo "Configuring with preset: $(PRESET)"
	cmake --preset $(PRESET)

#------------------------------------------------------------------------------
# clean - Remove build artifacts (using cmake -E for cross-platform compatibility)
#------------------------------------------------------------------------------
clean:
	@echo "Cleaning build artifacts..."
	-cmake -E rm -rf $(BUILD_DIR)
	-cmake -E rm -rf $(DEPS_DIR)
	@echo "Clean complete."

#------------------------------------------------------------------------------
# setup - Install build dependencies (vcpkg)
#------------------------------------------------------------------------------
setup:
	@echo "Setting up build dependencies..."
	@$(PYTHON) scripts/setup_deps.py

#------------------------------------------------------------------------------
# install - Install to system (placeholder for future use)
#------------------------------------------------------------------------------
install: build
	@echo "Installing Sindarin SDK dependencies..."
	@cmake --install $(BUILD_DIR)

#------------------------------------------------------------------------------
# help - Show available targets
#------------------------------------------------------------------------------
help:
	@echo "Sindarin SDK - Build System"
	@echo ""
	@echo "Quick Start:"
	@echo "  make setup        Install vcpkg dependencies"
	@echo "  make build        Build and copy dependencies to deps/"
	@echo ""
	@echo "Build Targets:"
	@echo "  make build        Build SDK (auto-detects platform)"
	@echo "  make rebuild      Clean and build"
	@echo "  make configure    Configure CMake only"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Setup:"
	@echo "  make setup        Install build dependencies (vcpkg)"
	@echo ""
	@echo "CMake Presets (Advanced):"
	@echo "  cmake --preset linux-gcc-release    Linux with GCC"
	@echo "  cmake --preset linux-clang-release  Linux with Clang"
	@echo "  cmake --preset windows-clang-release Windows with Clang"
	@echo "  cmake --preset macos-clang-release  macOS with Clang"
	@echo ""
	@echo "  Then: cmake --build --preset <preset-name>"
	@echo ""
	@echo "Platform: $(PLATFORM)"
	@echo "Preset: $(PRESET)"
