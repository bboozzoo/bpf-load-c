# bpf-load-c — Compile C to eBPF device cgroup filter (no libbpf)
#
# Usage:
#   make            — build everything (requires clang, python3, gcc)
#   make header     — generate output/policy.h from src/policy.c
#   make loader     — build the bpf-load binary
#   make clean      — remove build artifacts

.PHONY: all header loader clean check-deps install-deps

CC       := clang-22
CFLAGS   ?= -target bpf -O2 -Wall -c
HOST_CC  := gcc
HOST_CFLAGS ?= -Wall -O2 -std=gnu11
PYTHON   := python3

SRC_DIR    = src
OUT_DIR    = output
TOOLS_DIR  = tools

POLICY_SRC = $(SRC_DIR)/policy.c
POLICY_O   = $(OUT_DIR)/policy.o
POLICY_H   = $(OUT_DIR)/policy.h
LOADER_SRC = $(SRC_DIR)/loader.c
LOADER_BIN = bpf-load

# ── Top-level targets ────────────────────────────────────────────────────

all: check-deps header loader
	@echo "=== Build complete ==="
	@echo "Run: ./bpf-load <cgroup-path> [command...]"

header: $(POLICY_H)

loader: $(LOADER_BIN)

# ── Dependency checks ────────────────────────────────────────────────────

check-deps:
	@ok=1; \
	command -v $(CC) >/dev/null 2>&1 || { echo "ERROR: $(CC) not found. Install: zypper install clang"; ok=0; }; \
	command -v $(HOST_CC) >/dev/null 2>&1 || { echo "ERROR: gcc not found."; ok=0; }; \
	command -v $(PYTHON) >/dev/null 2>&1 || { echo "ERROR: python3 not found."; ok=0; }; \
	$(PYTHON) -c "import elftools" 2>/dev/null || { echo "NOTE: pyelftools not found. Run: make install-deps"; }; \
	test $$ok -eq 1 || exit 1

install-deps:
	pip install pyelftools

# ── BPF object file: C → ELF .o ──────────────────────────────────────────

$(POLICY_O): $(POLICY_SRC) $(SRC_DIR)/bpf_types.h $(SRC_DIR)/bpf_helpers.h
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# ── C header: ELF .o → #include-able .h ──────────────────────────────────

$(POLICY_H): $(POLICY_O) $(TOOLS_DIR)/elf2header.py
	@mkdir -p $(OUT_DIR)
	$(PYTHON) $(TOOLS_DIR)/elf2header.py $(POLICY_O) $@ --source $(POLICY_SRC)

# ── Runtime loader: C → executable ───────────────────────────────────────

$(LOADER_BIN): $(LOADER_SRC) $(POLICY_H) $(SRC_DIR)/bpf_types.h
	$(HOST_CC) $(HOST_CFLAGS) -o $@ $(LOADER_SRC)

# ── Clean ─────────────────────────────────────────────────────────────────

clean:
	rm -rf $(OUT_DIR) $(LOADER_BIN)
