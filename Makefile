# Sindarin SDK Package

.PHONY: setup test

%.sn: %.sn.c
	@:

ifeq ($(OS),Windows_NT)
    EXE_EXT := .exe
else
    EXE_EXT :=
endif

BIN_DIR      := bin
SN           ?= sn
PYTHON       ?= python3
SRC_SOURCES  := $(wildcard src/*/*.sn)
RUN_TESTS_SN := .sn/sindarin-pkg-test/src/execute.sn
RUN_TESTS    := $(BIN_DIR)/run_tests$(EXE_EXT)

setup:
	@$(SN) --install

test: setup $(RUN_TESTS)
	@$(PYTHON) scripts/run_tests_with_diagnostics.py --compiler "$(SN)" --runner "$(RUN_TESTS)"
	@$(PYTHON) scripts/check_bytes_native.py --compiler "$(SN)"
	@$(PYTHON) scripts/check_bytes_native.py --compiler "$(SN)" --module binaryfile

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(RUN_TESTS): $(RUN_TESTS_SN) $(SRC_SOURCES) | $(BIN_DIR)
	@$(SN) $(RUN_TESTS_SN) -o $@ -l 1
