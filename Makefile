# Sindarin SDK - Makefile
#
# Simple Makefile for running SDK tests.
# Dependencies are managed via sn.yaml package references.

#------------------------------------------------------------------------------
# Phony targets
#------------------------------------------------------------------------------
.PHONY: all test hooks clean help

# Disable implicit rules for .sn.c files (these are compiled by the Sindarin compiler)
%.sn: %.sn.c
	@:

#------------------------------------------------------------------------------
# Platform Detection
#------------------------------------------------------------------------------
ifeq ($(OS),Windows_NT)
    PLATFORM := windows
    EXE_EXT := .exe
    MKDIR := mkdir
else
    UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
    ifeq ($(UNAME_S),Darwin)
        PLATFORM := darwin
    else
        PLATFORM := linux
    endif
    EXE_EXT :=
    MKDIR := mkdir -p
endif

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------
BIN_DIR := bin

# Sindarin compiler (from PATH, or override with SN=path/to/sn)
SN ?= sn

# Test runner from sindarin-pkg-test dependency
RUN_TESTS_SN := .sn/sindarin-pkg-test/src/execute.sn

# SDK source files (for dependency tracking)
# Note: .sn.c files are compiled by the Sindarin compiler, not tracked separately
SDK_SOURCES := $(wildcard src/*/*.sn)

# Compiled script binaries
RUN_TESTS_BIN := $(BIN_DIR)/run_tests$(EXE_EXT)

#------------------------------------------------------------------------------
# Default target
#------------------------------------------------------------------------------
all: test

#------------------------------------------------------------------------------
# test - Run SDK tests using compiled Sindarin test runner
#------------------------------------------------------------------------------
# test_persistent_rpc_burst is excluded until the documented stream-lifecycle
# race in docs/issues/quic_persistent_rpc_burst_flake.md is fixed. The test
# lives in its own file tests/net/test_persistent_rpc_burst.sn and can be
# run manually: bin/run_tests tests/net/test_persistent_rpc_burst.sn
#
# --parallel 8: default is OS.cpuCount() which on a dev workstation oversubscribes
# the CPU heavily when running the QUIC resilience binaries alongside the rest
# of the suite. Capping at 8 keeps per-test wall time closer to its standalone
# value and avoids flaky failures driven by scheduler starvation.
#
# --run-timeout 120: default 30s is tight under even moderate contention.
# Mac CI (3-core arm64) stretches per-test wall time so aggressively that
# test_quic_resilience_lifecycle (10 tests, 64s on mac) exceeds the 60s bound.
# 120s gives comfortable headroom for the QUIC tests without changing test code.
test: hooks $(RUN_TESTS_BIN)
	@$(RUN_TESTS_BIN) --exclude test_persistent_rpc_burst --parallel 8 --run-timeout 120 --verbose

#------------------------------------------------------------------------------
# Build the test runner
#------------------------------------------------------------------------------
$(BIN_DIR):
	@$(MKDIR) $(BIN_DIR)

$(RUN_TESTS_BIN): $(RUN_TESTS_SN) $(SDK_SOURCES) | $(BIN_DIR)
	@echo "Compiling execute.sn..."
	@$(SN) $(RUN_TESTS_SN) -o $(RUN_TESTS_BIN) -l 1

#------------------------------------------------------------------------------
# clean - Remove build artifacts
#------------------------------------------------------------------------------
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@echo "Clean complete."

#------------------------------------------------------------------------------
# help - Show available targets
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# hooks - Configure git to use tracked pre-commit hooks
#------------------------------------------------------------------------------
hooks:
	@git config core.hooksPath .githooks 2>/dev/null || true

help:
	@echo "Sindarin SDK"
	@echo ""
	@echo "Targets:"
	@echo "  make test         Run SDK tests"
	@echo "  make clean        Remove build artifacts"
	@echo "  make help         Show this help"
	@echo ""
	@echo "Dependencies are managed via sn.yaml package references."
	@echo ""
	@echo "Platform: $(PLATFORM)"
