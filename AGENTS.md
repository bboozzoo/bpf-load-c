# AGENTS.md — AI Agent Guide for bpf-load-c

## What This Project Does

Compiles C to eBPF and loads it as a `BPF_PROG_TYPE_CGROUP_DEVICE` program
**without libbpf** at runtime.  The motivating use case is replacing snapd's
hand-written BPF assembly with maintainable C.

## Architecture

```
src/policy.c  ──clang -target bpf──▶  output/policy.o  ──elf2header.py──▶  output/policy.h
                                                                                │
                                                                         #include
                                                                                │
src/loader.c  ────────────────gcc───────────────────────────────────────────▶  bpf-load
```

The build is a **three-stage pipeline**:
1. **BPF compilation**: `clang -target bpf -O2 -c policy.c → policy.o` (ELF)
2. **Header generation**: `elf2header.py policy.o → policy.h` (C header with
   raw insn bytes + map descriptors)
3. **Loader compilation**: `gcc loader.c → bpf-load` (links nothing but libc)

## Key Files

| File | Role | Notes |
|---|---|---|
| `src/bpf_types.h` | Kernel UAPI types | Defines `struct bpf_cgroup_dev_ctx`, BPF constants, `struct bpf_insn`. Guarded with `#ifndef __LINUX_BPF_H__` — used by clang BPF but skipped when `<linux/bpf.h>` is available (gcc loader). |
| `src/bpf_helpers.h` | BPF helper stubs | `bpf_map_lookup_elem` declaration, `SEC()` macro. Only included by `policy.c`. |
| `src/policy.c` | BPF device filter | The C eBPF program — device allowlist matching snapd's logic. Uses a hash map for allowed devices. |
| `src/loader.c` | Runtime loader | Uses raw `bpf()` syscall. Includes `<linux/bpf.h>` for `union bpf_attr`. Creates maps, patches fds, loads+attaches program. |
| `tools/elf2header.py` | ELF → C header | Parses BPF ELF with `pyelftools`. Extracts `.text`/code section, finds map relocations, generates `output/policy.h`. |
| `output/policy.o` | Committed artifact | BPF ELF object — committed so loader can be built without clang. |
| `output/policy.h` | Committed artifact | Generated C header — `policy_insns[]` bytes, `policy_maps[]` descriptors, metadata. `#include`-able. |
| `Makefile` | Build orchestration | Targets: `all`, `header`, `loader`, `clean`, `check-deps`, `install-deps`. |

## Constraints (Always Enforced)

- **No libbpf at runtime.** Build-time LLVM tools (clang, llvm-objcopy) are
  acceptable. The `bpf-load` binary must not link libbpf.
- **No BTF.** No CO-RE, no BTF type information. Kernel types are defined
  locally in `bpf_types.h`.
- **No cmake.** Simple Makefile only.
- **Generated artifacts are committed.** `output/policy.o` and `output/policy.h`
  live in the tree. Running `make` regenerates them but the committed versions
  are the primary build source for the loader.
- **Reproducibility.** The generated header must embed clang version and source
  SHA-256 so a reviewer can verify the bytecode matches the source.
- **`#include`-able output.** `policy.h` is a standalone C header — it does not
  require any other project headers to compile.

## Map Relocation Handling

clang emits `BPF_LD_MAP_FD` pseudo-instructions (2 insns: `ld_dw` + zero) with
ELF `R_BPF_64_64` relocations. `elf2header.py`:

1. Finds the code section (any non-empty PROGBITS section, e.g. `cgroup/dev`)
2. Finds the corresponding `.rel<section>` relocation section
3. For each relocation pointing to a `.maps` symbol, records the byte offset of
   the `imm32` field of the `ld_dw` instruction
4. Also reads map properties (type, key/value size, max entries) from the
   `.maps` section data

The loader then creates each map, patches its fd into the instruction bytes at
the recorded offsets, loads the program, and attaches it to a cgroup.

## Dependencies

| Tool | Needed for | Install |
|---|---|---|
| clang (≥14, with BPF target) | `policy.c` → `policy.o` | `zypper install clang` |
| python3 + pyelftools | `policy.o` → `policy.h` | `pip install pyelftools` |
| gcc | `loader.c` → `bpf-load` | Pre-installed |
| Linux headers (`<linux/bpf.h>`) | loader compilation | Pre-installed on Linux |

## Runtime Requirements

- Linux 5.10+ (matching snapd's target)
- BPF operations need either **root** or `kernel.unprivileged_bpf_disabled=0`
- On pre-5.11 kernels, BPF map/prog creation requires `RLIMIT_MEMLOCK` (the
  loader adjusts this automatically)

## Edge Cases & Gotchas

- **GCC 15+** rejects anonymous union members with duplicate field names. The
  loader uses `<linux/bpf.h>` (which uses a merged-struct approach) instead of
  defining its own `union bpf_attr`.
- **clang version varies.** The Makefile defaults to `clang-22` but can be
  overridden: `make CC=clang-19`. `elf2header.py` tries versioned names
  automatically.
- **Code section naming.** With `SEC("cgroup/dev")`, the code lands in a section
  named `cgroup/dev`, not `.text`. `elf2header.py` auto-detects the code section.
- **Policy changes.** If `policy.c` changes, run `make header` to regenerate
  `policy.h`, then rebuild the loader. Commit both regenerated artifacts.
