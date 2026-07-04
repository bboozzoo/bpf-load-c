#!/usr/bin/env python3
"""
elf2header.py — Convert a BPF ELF object file into a #include-able C header.

Usage:
  python3 tools/elf2header.py <input.o> <output.h> [--source <c_file>]

The input should be a BPF ELF object produced by `clang -target bpf -c`.
The output is a C header with:
  - policy_insns[]     : raw BPF instruction bytes
  - policy_maps[]      : map descriptors (type, key/value sizes, patch offsets)
  - Metadata            : clang version, source SHA-256
"""

import argparse
import hashlib
import os
import struct
import subprocess
import sys

# ── BPF relocation types ────────────────────────────────────────────────
R_BPF_64_64    = 1
R_BPF_64_ABS64 = 2

# ── BPF pseudo-instruction markers ──────────────────────────────────────
BPF_PSEUDO_MAP_FD = 1


def fail(msg: str):
    print(f"elf2header: error: {msg}", file=sys.stderr)
    sys.exit(1)


def get_clang_version() -> str:
    """Return the first line of `clang --version`."""
    # Try versioned names first (common on distros that ship multiple LLVM versions)
    for clang_name in ("clang-22", "clang-21", "clang-20", "clang-19", "clang-18",
                        "clang-17", "clang-16", "clang-15", "clang-14", "clang"):
        try:
            out = subprocess.check_output([clang_name, "--version"],
                                          stderr=subprocess.DEVNULL,
                                          text=True)
            return out.split("\n")[0].strip()
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError:
            continue
    return "clang not found"


def sha256_file(path: str) -> str:
    """Return hex SHA-256 digest of file contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def dump_insn_bytes(data: bytes, f):
    """Write byte array initializer, 8 bytes per line with instruction index."""
    insn_count = len(data) // 8
    for i in range(insn_count):
        offset = i * 8
        eight = data[offset:offset + 8]
        hex_bytes = ", ".join(f"0x{b:02x}" for b in eight)
        f.write(f"    {hex_bytes},  /* {i:3d} */\n")


def generate_header(input_path: str, output_path: str, source_path: str = None):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        fail("pyelftools not found. Install with: pip install pyelftools")

    # Keep file handle open — ELFFile uses lazy loading from the stream
    fh = open(input_path, "rb")
    elf = ELFFile(fh)

    # ── Find the BPF code section ─────────────────────────────────────
    # With clang -target bpf, the code lands in whichever section the
    # SEC("name") attribute specifies (e.g. "cgroup/dev", ".text", etc.).
    # We look for a PROGBITS section that has non-zero size and is
    # referenced by STT_FUNC symbols (i.e. the actual BPF instructions).
    code_section = None
    code_section_name = None

    # First pass: try .text (common fallback)
    text_sec = elf.get_section_by_name(".text")
    if text_sec and text_sec.data_size > 0:
        code_section = text_sec
        code_section_name = ".text"

    # Second pass: look for any non-zero PROGBITS section containing BPF code
    if code_section is None:
        for i in range(elf.num_sections()):
            sec = elf.get_section(i)
            if sec is None:
                continue
            name = sec.name
            # Skip known non-code sections
            if name in (".text", ".maps", ".strtab", ".symtab", ".llvm_addrsig",
                         ".bss", ".data", ".rodata", ""):
                continue
            if sec.data_size > 0:
                code_section = sec
                code_section_name = name
                break

    if code_section is None:
        fail("no code section found in ELF (no non-empty PROGBITS section)")

    text_data = code_section.data()
    text_addr = code_section["sh_addr"]

    print(f"elf2header: using code section '{code_section_name}' ({len(text_data)} bytes)")

    # ── Find corresponding relocation section ─────────────────────────
    rel_sections = []
    # Try .rel{code_section_name} and .rela{code_section_name}
    for rel_prefix in (".rel", ".rela"):
        rel_name = rel_prefix + code_section_name
        rel_sec = elf.get_section_by_name(rel_name)
        if rel_sec:
            rel_sections.append(rel_sec)
    # Also try .rel.text if we found a different code section (some clang versions)
    rel_text = elf.get_section_by_name(".rel.text")
    if rel_text and rel_text not in rel_sections:
        rel_sections.append(rel_text)
    rela_text = elf.get_section_by_name(".rela.text")
    if rela_text and rela_text not in rel_sections:
        rel_sections.append(rela_text)

    # ── Locate .maps section ────────────────────────────────────────────
    maps_section = elf.get_section_by_name(".maps")
    maps_data = maps_section.data() if maps_section else b""
    maps_addr = maps_section["sh_addr"] if maps_section else 0

    # ── Build map symbol index ───────────────────────────────────────────
    # symbol name → { size, offset_in_maps_section }
    map_symbols = {}
    symtab = elf.get_section_by_name(".symtab")
    if symtab:
        for sym in symtab.iter_symbols():
            sym_section_idx = sym["st_shndx"]
            # Resolve section index to actual section
            if isinstance(sym_section_idx, int) and sym_section_idx >= 0 and sym_section_idx < elf.num_sections():
                sym_sec = elf.get_section(sym_section_idx)
                if sym_sec and sym_sec.name == ".maps":
                    map_symbols[sym.name] = {
                        "size":   sym["st_size"],
                        "offset": sym["st_value"],  # offset within .maps
                    }

    # ── Find relocations referencing map symbols ──────────────────────────
    # map_name → list of byte offsets in code section
    map_patches = {}

    # Collect all relocations from the relocation sections we found
    relocations = []
    for rel_sec in rel_sections:
        for rel in rel_sec.iter_relocations():
            relocations.append(rel)

    # In BPF ELF, relocations are REL type:
    #   r_offset = byte offset within the code section
    #   r_info   = ELF64_R_INFO(sym_index, reloc_type)
    #   There's no r_addend field in REL; addend is stored in-place.
    for rel in relocations:
        # Get relocation type and symbol
        r_type = rel["r_info_type"]
        sym_index = rel["r_info_sym"]

        # Only handle R_BPF_64_64 (and R_BPF_64_ABS64 as fallback)
        if r_type not in (R_BPF_64_64, R_BPF_64_ABS64):
            continue

        # Get the symbol
        if symtab is None:
            continue
        sym = symtab.get_symbol(sym_index)
        if sym is None:
            continue

        sym_name = sym.name
        if sym_name not in map_symbols:
            continue

        # The r_offset is the byte offset of the instruction within .text
        insn_offset = rel["r_offset"]

        # Map fd is patched at insn_offset + 4 (the imm32 field of insn_ld_dw)
        patch_offset = insn_offset + 4

        if sym_name not in map_patches:
            map_patches[sym_name] = []
        map_patches[sym_name].append(patch_offset)

    # ── Extract map properties from .maps section ────────────────────────
    # Each map struct is {uint32_t type, uint32_t key_size, uint32_t value_size,
    #                      uint32_t max_entries} = 16 bytes.
    # Values are stored in ELF native endianness (little-endian on BPF target).
    map_props = {}
    for name, info in map_symbols.items():
        off = info["offset"]
        if off + 16 <= len(maps_data):
            raw = maps_data[off:off + 16]
            mtype, ksize, vsize, maxe = struct.unpack("<IIII", raw)
            map_props[name] = {
                "type":        mtype,
                "key_size":    ksize,
                "value_size":  vsize,
                "max_entries": maxe,
            }
        else:
            # Fallback defaults
            map_props[name] = {
                "type":        1,     # BPF_MAP_TYPE_HASH
                "key_size":    9,
                "value_size":  1,
                "max_entries": 1000,
            }

    # ── Metadata ─────────────────────────────────────────────────────────
    clang_ver = get_clang_version()
    src_hash  = ""
    src_name  = ""
    if source_path:
        src_name = source_path
        if os.path.isfile(source_path):
            src_hash = sha256_file(source_path)
        else:
            src_hash = "source file not found"

    # ── Generate output header ───────────────────────────────────────────
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write("/*\n")
        f.write(" * AUTOGENERATED — do not edit.\n")
        f.write(" * Generated by: tools/elf2header.py\n")
        f.write(f" * Input:        {os.path.basename(input_path)}\n")
        if src_name:
            f.write(f" * Source:       {src_name}\n")
        f.write(f" * Clang:        {clang_ver}\n")
        if src_hash:
            f.write(f" * Source SHA256: {src_hash}\n")
        f.write(" */\n\n")
        f.write("#ifndef POLICY_H\n")
        f.write("#define POLICY_H\n\n")
        f.write("#include <stdint.h>\n")
        f.write("#include <stddef.h>\n\n")

        # ── BPF program instructions ────────────────────────────────────
        f.write("/* ── BPF program instructions ────────────────────────────────────────── */\n\n")
        f.write("static const uint8_t policy_insns[] = {\n")
        dump_insn_bytes(text_data, f)
        f.write("};\n\n")

        insn_count = len(text_data) // 8
        f.write(f"static const size_t policy_insns_len = {len(text_data)};\n")
        f.write(f"static const size_t policy_insns_cnt = {insn_count};\n\n")

        # ── Map descriptors ─────────────────────────────────────────────
        f.write("/* ── Map descriptors ─────────────────────────────────────────────────── */\n")
        f.write("/*\n")
        f.write(" * Map fd is embedded via BPF_LD_MAP_FD (two insns: ld_dw + zero).\n")
        f.write(" * patch_offsets point to the imm32 field of the ld_dw instruction.\n")
        f.write(" * The loader writes the fd in host byte order — the kernel interprets\n")
        f.write(" * bpf_insn.imm as native __s32, matching how clang emits instructions.\n")
        f.write(" */\n")
        f.write("\n")
        f.write("struct policy_map_desc {\n")
        f.write("    const char    *name;\n")
        f.write("    uint32_t       type;          /* BPF_MAP_TYPE_* */\n")
        f.write("    uint32_t       key_size;\n")
        f.write("    uint32_t       value_size;\n")
        f.write("    uint32_t       max_entries;\n")
        f.write("    uint32_t       fd;            /* filled by loader at runtime */\n")
        f.write("    size_t         num_patches;\n")
        f.write("    const size_t  *patch_offsets; /* byte offsets into policy_insns */\n")
        f.write("};\n\n")

        # Emit a static patch-offset array for each map
        patch_arrays = {}
        for name, patches in sorted(map_patches.items()):
            # Make a safe C identifier from the symbol name
            safe_name = name.replace(".", "_").replace("-", "_")
            arr_name = f"_policy_map_{safe_name}_patches"
            f.write(f"static const size_t {arr_name}[] = {{\n")
            for p in sorted(patches):
                f.write(f"    {p},\n")
            f.write("};\n\n")
            patch_arrays[name] = arr_name

        # Emit the maps array
        f.write("static struct policy_map_desc policy_maps[] = {\n")
        for name, patches in sorted(map_patches.items()):
            props = map_props.get(name, {
                "type": 1, "key_size": 9, "value_size": 1, "max_entries": 1000
            })
            arr_name = patch_arrays[name]
            f.write("    {\n")
            f.write(f'        .name          = "{name}",\n')
            f.write(f"        .type          = {props['type']},   /* BPF_MAP_TYPE_* */\n")
            f.write(f"        .key_size      = {props['key_size']},\n")
            f.write(f"        .value_size    = {props['value_size']},\n")
            f.write(f"        .max_entries   = {props['max_entries']},\n")
            f.write("        .fd            = (uint32_t)-1,\n")
            f.write(f"        .num_patches   = {len(patches)},\n")
            f.write(f"        .patch_offsets = {arr_name},\n")
            f.write("    },\n")

        # Handle case with no maps at all
        if not map_patches:
            f.write("    /* No maps found in the BPF program */\n")

        f.write("};\n\n")
        f.write(f"static const size_t policy_maps_count = sizeof(policy_maps) / sizeof(policy_maps[0]);\n\n")

        # ── Metadata ────────────────────────────────────────────────────
        f.write("/* ── Metadata ────────────────────────────────────────────────────────── */\n\n")
        f.write(f'static const char policy_source[]   = "{src_name}";\n')
        f.write(f'static const char policy_clang[]    = "{clang_ver}";\n')
        f.write(f'static const char policy_sha256[]   = "{src_hash}";\n\n')

        f.write("#endif /* POLICY_H */\n")

    fh.close()

    print(f"elf2header: wrote {output_path}")
    if map_patches:
        for name in sorted(map_patches):
            print(f"  map '{name}': {len(map_patches[name])} patch offset(s)")
    else:
        print("  no map relocations found")
    print(f"  {insn_count} instructions ({len(text_data)} bytes)")
    if src_hash:
        print(f"  source SHA256: {src_hash}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert BPF ELF object to #include-able C header")
    parser.add_argument("input", help="BPF ELF object file (.o)")
    parser.add_argument("output", help="Output C header (.h)")
    parser.add_argument("--source", default=None,
                        help="Original C source file (for metadata/hash)")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        fail(f"input file not found: {args.input}")

    generate_header(args.input, args.output, args.source)


if __name__ == "__main__":
    main()
