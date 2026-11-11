# xks-id
#
#   make                  the engine (out/xksid, C17) and the interface (xksid-tui, Rust)
#   make out/xksid        the engine alone: needs a C compiler and nothing else
#   make check            the tests
#   make install          binaries to $(PREFIX)/bin, the service file to ~/.config/systemd/user
#   make install-vectors VECTORS=DIR
#                         dvec.tok, dvec.vec.f32 and dvec.head from DIR to $(MODEL_DIR)
#
# Only for someone who builds a vector table from a decision model (docs/VECTORS.md).
# These tools link llama.cpp (b11960 or newer, built as shared libraries):
#   make distil LLAMA_DIR=/path/to/llama.cpp LLAMA_BUILD=/path/to/llama.cpp/build

CC        ?= cc
CFLAGS    ?= -std=c17 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wstrict-prototypes -Werror
CXX       ?= g++
CXXFLAGS  ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror
PREFIX    ?= $(HOME)/.local
MODEL_DIR ?= $(HOME)/.local/share/xksid
UNIT_DIR  ?= $(HOME)/.config/systemd/user

XKSID_SRC = src/xksid/xksid.c src/xksid/rules.c src/xksid/sha256.c src/xksid/tok.c src/xksid/vec.c
XKSID_HDR = src/xksid/rules.h src/xksid/sha256.h src/xksid/tok.h src/xksid/vec.h
TUI       = tui/target/release/xksid-tui

LLAMA_INC = -isystem $(LLAMA_DIR)/src -isystem $(LLAMA_DIR)/include -isystem $(LLAMA_DIR)/ggml/include \
            -isystem $(LLAMA_DIR)/common -isystem $(LLAMA_DIR)/vendor
LLAMA_LIB = -L$(LLAMA_BUILD)/bin -lllama-common -lllama -lggml-base -Wl,-rpath,$(LLAMA_BUILD)/bin

.PHONY: all tui check install install-vectors distil
all: out/xksid tui

out/xksid: $(XKSID_SRC) $(XKSID_HDR)
	@mkdir -p out
	$(CC) $(CFLAGS) $(XKSID_SRC) -lm -o $@

tui:
	cd tui && cargo build --release --offline

out/xksid-fit: src/xksid/fit.c src/xksid/tok.c src/xksid/vec.c src/xksid/tok.h src/xksid/vec.h
	@mkdir -p out
	$(CC) $(CFLAGS) src/xksid/fit.c src/xksid/tok.c src/xksid/vec.c -lm -o $@

out/vec_test: tests/vec_test.c src/xksid/vec.c src/xksid/vec.h
	@mkdir -p out
	$(CC) $(CFLAGS) tests/vec_test.c src/xksid/vec.c -lm -o $@

check: out/xksid out/vec_test
	out/vec_test
	sh tests/run.sh

install: all
	install -d $(PREFIX)/bin $(UNIT_DIR)
	install -m 755 out/xksid $(PREFIX)/bin/xksid
	install -m 755 $(TUI) $(PREFIX)/bin/xksid-tui
	install -m 644 integrations/systemd/xksid.service $(UNIT_DIR)/xksid.service
	@echo "installed. Nothing was started or enabled: docs/SETUP.md has the next steps."

install-vectors:
	@test -n "$(VECTORS)" || { echo "set VECTORS to the directory that holds dvec.tok, dvec.vec.f32 and dvec.head"; exit 1; }
	install -d $(MODEL_DIR)
	install -m 644 $(VECTORS)/dvec.tok $(VECTORS)/dvec.vec.f32 $(VECTORS)/dvec.head $(MODEL_DIR)/

distil: out/xksid-distil out/xksid-tokpack out/xksid-fit

out/xksid-tokpack: src/distil/xksid-tokpack.cpp
	@test -n "$(LLAMA_DIR)" -a -n "$(LLAMA_BUILD)" || { echo "set LLAMA_DIR and LLAMA_BUILD"; exit 1; }
	@mkdir -p out
	$(CXX) $(CXXFLAGS) $(LLAMA_INC) $< $(LLAMA_LIB) -o $@

out/xksid-distil: src/distil/xksid-distil.cpp
	@test -n "$(LLAMA_DIR)" -a -n "$(LLAMA_BUILD)" || { echo "set LLAMA_DIR and LLAMA_BUILD"; exit 1; }
	@mkdir -p out
	@printf '%s\n' -xc++ $(CXXFLAGS) $(LLAMA_INC) > src/distil/compile_flags.txt
	$(CXX) $(CXXFLAGS) $(LLAMA_INC) $< $(LLAMA_LIB) -o $@
