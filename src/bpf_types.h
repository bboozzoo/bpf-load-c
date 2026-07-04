/*
 * Minimal BPF type definitions for building without depending on specific
 * kernel header versions.  These are stable UAPI types; definitions are
 * compatible with the Linux kernel's include/uapi/linux/bpf.h.
 *
 * Used by both the BPF C program (compiled with clang -target bpf) and
 * the runtime loader (compiled with gcc).
 */

#ifndef BPF_TYPES_H
#define BPF_TYPES_H

#include <stdint.h>

/*
 * When <linux/bpf.h> is available (host/gcc compilation), skip our
 * definitions to avoid redefinition conflicts.  Our BPF program
 * (clang -target bpf) doesn't have kernel headers, so these are
 * needed there.
 */
#ifndef __LINUX_BPF_H__

/* ── BPF instruction (UAPI stable) ─────────────────────────────────────── */

struct bpf_insn {
    uint8_t  code;       /* opcode */
    uint8_t  dst_reg:4;  /* dest register */
    uint8_t  src_reg:4;  /* source register */
    int16_t  off;        /* signed offset */
    int32_t  imm;        /* signed immediate constant */
};

/* ── BPF registers ─────────────────────────────────────────────────────── */

#define BPF_REG_0   0
#define BPF_REG_1   1
#define BPF_REG_2   2
#define BPF_REG_3   3
#define BPF_REG_4   4
#define BPF_REG_5   5
#define BPF_REG_6   6
#define BPF_REG_7   7
#define BPF_REG_8   8
#define BPF_REG_9   9
#define BPF_REG_10  10

/* ── BPF instruction classes ───────────────────────────────────────────── */

#define BPF_LD      0x00
#define BPF_LDX     0x01
#define BPF_ST      0x02
#define BPF_STX     0x03
#define BPF_ALU     0x04
#define BPF_JMP     0x05
#define BPF_ALU64   0x07
#define BPF_JMP32   0x06

/* ── BPF instruction sizes ─────────────────────────────────────────────── */

#define BPF_W       0x00    /* 32-bit */
#define BPF_H       0x08    /* 16-bit */
#define BPF_B       0x10    /* 8-bit  */
#define BPF_DW      0x18    /* 64-bit */

/* ── BPF source operand ────────────────────────────────────────────────── */

#define BPF_K       0x00
#define BPF_X       0x08
#define BPF_IMM     0x00

/* ── BPF modes ─────────────────────────────────────────────────────────── */

#define BPF_IMM     0x00
#define BPF_ABS     0x20
#define BPF_IND     0x40
#define BPF_MEM     0x60

/* ── Pseudo-instruction marker for map fd embedding ────────────────────── */

#define BPF_PSEUDO_MAP_FD  1

/* ── bpf_cgroup_dev_ctx (UAPI stable) ──────────────────────────────────── */

struct bpf_cgroup_dev_ctx {
    uint32_t access_type;
    uint32_t major;
    uint32_t minor;
};

/* access_type is encoded as (BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_* */

#define BPF_DEVCG_DEV_BLOCK    2
#define BPF_DEVCG_DEV_CHAR     1

#define BPF_DEVCG_ACC_READ     (1 << 0)
#define BPF_DEVCG_ACC_WRITE    (1 << 1)
#define BPF_DEVCG_ACC_MKNOD    (1 << 2)

/* ── BPF program / map / attach types (UAPI stable) ────────────────────── */

#define BPF_PROG_TYPE_CGROUP_DEVICE  9

#define BPF_MAP_TYPE_HASH            1

#define BPF_CGROUP_DEVICE            8     /* attach type */

#define BPF_ANY                      0     /* map update: upsert */

/* ── BPF helper function IDs (UAPI stable) ─────────────────────────────── */

#define BPF_FUNC_map_lookup_elem     1

/* ── BPF syscall commands ──────────────────────────────────────────────── */

#define BPF_MAP_CREATE               0
#define BPF_MAP_UPDATE_ELEM          2
#define BPF_MAP_DELETE_ELEM          3
#define BPF_MAP_GET_NEXT_KEY         4
#define BPF_PROG_LOAD                5
#define BPF_OBJ_PIN                  6
#define BPF_OBJ_GET                  7
#define BPF_PROG_ATTACH              8

/* ── BPF object name length ────────────────────────────────────────────── */

#define BPF_OBJ_NAME_LEN             16

/* ── bpf_attr (minimal, for map create / prog load / attach) ───────────── */
/*
 * The union bpf_attr is only needed by the host loader (compiled with gcc).
 * It is excluded from BPF-targeted compilation because clang's -target bpf
 * mode rejects anonymous union members with overlapping field names.
 *
 * For the loader, we use the system's <linux/bpf.h> which is always
 * available on Linux and avoids version-compatibility issues.
 * Include <linux/bpf.h> from the host compiler to get the actual
 * bpf_attr definition.
 */
#ifndef __bpf__
/* union bpf_attr is provided by <linux/bpf.h> — included by loader.c */
#endif /* !__bpf__ */

#endif /* !__LINUX_BPF_H__ */

#endif /* BPF_TYPES_H */
