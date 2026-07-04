# bpf-load-c

Compile C to eBPF and load it as a `BPF_PROG_TYPE_CGROUP_DEVICE` program
**without libbpf** at runtime.

The motivating use case is replacing snapd's hand-written BPF assembly (device
cgroup allowlist at
[device-cgroup-support.c#L185-L241](https://github.com/canonical/snapd/blob/3f9c2337f3fce9458e34fcb806b052fdbffa072b/cmd/libsnap-confine-private/device-cgroup-support.c#L185-L241))
with reviewable, maintainable C code.

## Design

| Constraint | Approach |
|---|---|
| No libbpf at runtime | Raw `bpf()` syscall in the loader (`BPF_PROG_LOAD`, `BPF_PROG_ATTACH`) |
| No BTF | Kernel types defined locally in `src/bpf_types.h` |
| Reproducible build | Generated header embeds clang version + source SHA-256 |
| Committed artifacts | `output/policy.o` and `output/policy.h` are in-tree |
| `#include`-able output | `output/policy.h` is a standalone C header with insn bytes + map descriptors |

## Pipeline

```
src/policy.c         C BPF program (device allowlist — matches snapd logic)
    │  clang -target bpf -O2 -c
    ▼
output/policy.o      ELF object (committed)
    │  tools/elf2header.py
    ▼
output/policy.h      C header: raw insn bytes, map descriptors, metadata
    │  #include
    ▼
src/loader.c         Runtime loader (raw bpf() syscall)
    │  gcc
    ▼
bpf-load             CLI tool
```

## Build & Run

```bash
# One-time: install dependencies
make install-deps          # pip install pyelftools
# zypper install clang     # if clang not already present

# Build
make all CC=clang-22 HOST_CC=gcc

# Run (needs root or kernel.unprivileged_bpf_disabled=0)
sudo ./bpf-load /sys/fs/cgroup/<cgroup-path> [command...]
```

### Targets

| Target | What it does |
|---|---|
| `make` / `make all` | Build everything |
| `make header` | `policy.c` → `output/policy.o` → `output/policy.h` |
| `make loader` | `loader.c` → `bpf-load` binary |
| `make check-deps` | Verify clang, gcc, python3, pyelftools |
| `make install-deps` | `pip install pyelftools` |
| `make clean` | Remove `output/` and `bpf-load` |

## Requirements

- **No BTF** — the BPF program and loader must not depend on BTF
- **Committed artifacts** — generated output (`policy.o`, `policy.h`) lives in
  the source tree so the loader can be built without clang
- **Reproducibility** — the generated header records clang version and source
  file SHA-256
- **`#include`-able** — `policy.h` is a standalone C header, directly
  importable with `#include "../output/policy.h"`
- **No libbpf at runtime** — build-time LLVM tools are fine, but the loader
  binary must not link against libbpf

## BPF Program Behavior

The device cgroup filter (`policy.c`) implements snapd's allowlist logic:

1. Extract `{type, major, minor}` from `struct bpf_cgroup_dev_ctx`
2. Decode device type (`b` = block, `c` = char) from `access_type & 0xFFFF`
3. Unknown type → **deny**
4. Exact `{type, major, minor}` hash-map lookup → found → **allow**
5. Retry with `minor = 0xFFFFFFFF` (wildcard any-minor) → found → **allow**
6. Otherwise → **deny**

Allowed devices are managed via a `BPF_MAP_TYPE_HASH` map (keyed by
`{uint8_t type, uint32_t major, uint32_t minor}`, 1-byte value).

## Map Handling Without libbpf

clang emits `BPF_LD_MAP_FD` pseudo-instructions with ELF relocations for each
map reference.  `elf2header.py` records the byte offsets where map fds must be
patched.  At load time, the loader:

1. Creates each map via `bpf(BPF_MAP_CREATE)`
2. Patches the map fd into the instruction byte array at the recorded offsets
3. Loads the program via `bpf(BPF_PROG_LOAD)`
4. Attaches to the cgroup via `bpf(BPF_PROG_ATTACH)`
