/*
 * loader.c — Load and attach a BPF_PROG_TYPE_CGROUP_DEVICE program
 *            using the raw bpf() syscall (no libbpf dependency).
 *
 * Usage:  bpf-load <cgroup-path> [command...]
 *
 * If no command is given, the program is loaded and attached, then exits.
 * If a command is given, the program also moves itself into the cgroup
 * and exec's the command under device filtering.
 *
 * Build:  gcc -Wall -O2 -o bpf-load src/loader.c
 *         (the generated output/policy.h is #included at compile time)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "bpf_types.h"

/* ── Generated header (produced by tools/elf2header.py) ───────────────── */
#include "../output/policy.h"

/* ── bpf() syscall wrapper ────────────────────────────────────────────── */

static int sys_bpf(int cmd, union bpf_attr *attr, size_t size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* ── RLIMIT_MEMLOCK adjustment (for pre-5.11 kernels) ─────────────────── */

static void adjust_memlock(void)
{
    struct rlimit lim = {0};
    if (getrlimit(RLIMIT_MEMLOCK, &lim) < 0) {
        perror("getrlimit(RLIMIT_MEMLOCK)");
        return;
    }
    const rlim_t min_memlock = 512UL * 1024UL;  /* 512 KB */
    if (lim.rlim_cur >= min_memlock)
        return;

    fprintf(stderr, "adjusting RLIMIT_MEMLOCK from %lu to %lu\n",
            (unsigned long)lim.rlim_cur, (unsigned long)min_memlock);

    lim.rlim_cur = min_memlock;
    if (lim.rlim_max < min_memlock)
        lim.rlim_max = min_memlock;

    if (setrlimit(RLIMIT_MEMLOCK, &lim) < 0) {
        perror("setrlimit(RLIMIT_MEMLOCK) — continuing anyway");
    }
}

/* ── Map creation ─────────────────────────────────────────────────────── */

static int create_maps(void)
{
    for (size_t i = 0; i < policy_maps_count; i++) {
        struct policy_map_desc *m = &policy_maps[i];

        union bpf_attr attr = {0};
        attr.map_type    = m->type;
        attr.key_size    = m->key_size;
        attr.value_size  = m->value_size;
        attr.max_entries = m->max_entries;
        strncpy(attr.map_name, m->name, sizeof(attr.map_name) - 1);

        int fd = sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
        if (fd < 0) {
            fprintf(stderr, "BPF_MAP_CREATE '%s' failed: %s\n",
                    m->name, strerror(errno));
            return -1;
        }
        m->fd = fd;
        fprintf(stderr, "created map '%s' (fd=%d, type=%u, key=%u, val=%u, entries=%u)\n",
                m->name, fd, m->type, m->key_size, m->value_size, m->max_entries);
    }
    return 0;
}

/* ── Close maps ───────────────────────────────────────────────────────── */

static void close_maps(void)
{
    for (size_t i = 0; i < policy_maps_count; i++) {
        if (policy_maps[i].fd != (uint32_t)-1)
            close(policy_maps[i].fd);
    }
}

/* ── Patch map fds into instruction stream ────────────────────────────── */

/*
 * Relocation patching (what and why)
 * ───────────────────────────────────
 *
 * When clang compiles C BPF code that calls bpf_map_lookup_elem(&devmap, ...),
 * it emits a BPF_LD_MAP_FD pseudo-instruction — actually TWO consecutive
 * 8-byte bpf_insn structs:
 *
 *   insn[N]   :  code = 0x18  (BPF_LD | BPF_DW | BPF_IMM)
 *                 dst  = 1     (R1 — first argument register for helper call)
 *                 src  = 1     (BPF_PSEUDO_MAP_FD — marks this as a map fd load)
 *                 imm  = 0     (PLACEHOLDER — lower 32 bits of map fd)
 *   insn[N+1] :  code = 0x00  (reserved — required by the 64-bit load encoding)
 *                 imm  = 0     (PLACEHOLDER — upper 32 bits of map fd, always 0)
 *
 *   insn[N+2] :  BPF_CALL  BPF_FUNC_map_lookup_elem  (the actual helper invocation)
 *
 * At compile time the map fd is unknown, so clang leaves the imm fields
 * zero and records an ELF R_BPF_64_64 relocation pointing to the map
 * symbol.  elf2header.py finds these relocations and emits patch_offsets[]
 * — each is the byte offset of the imm32 field of insn[N] within
 * policy_insns[].
 *
 * The total number of patch offsets for a given map equals the number of
 * bpf_map_lookup_elem() calls that reference that map.  In our case, two
 * calls to bpf_map_lookup_elem(&devmap, &key) → two relocations → two
 * patch offsets.
 *
 * At load time we create the map, get back an fd (a small int, so only the
 * lower 32 bits matter), then write that fd into each patch location in
 * host byte order.  The kernel interprets bpf_insn.imm as a native __s32,
 * matching how clang originally emitted every other instruction field.
 */
static void patch_map_fds(uint8_t *prog)
{
    for (size_t i = 0; i < policy_maps_count; i++) {
        struct policy_map_desc *m = &policy_maps[i];
        uint32_t fd = m->fd;

        for (size_t j = 0; j < m->num_patches; j++) {
            size_t off = m->patch_offsets[j];
            if (off + 4 > policy_insns_len) {
                fprintf(stderr, "WARNING: patch offset %zu out of range "
                        "(insns_len=%zu)\n", off, policy_insns_len);
                continue;
            }
            /* Write the map fd in host byte order (kernel interprets
               bpf_insn.imm as a native __s32 — same endianness as the
               clang-emitted instructions). */
            memcpy(&prog[off], &fd, sizeof(fd));
        }
    }
}

/* ── Load BPF program ─────────────────────────────────────────────────── */

static int load_prog(const uint8_t *insns, size_t insn_cnt)
{
    union bpf_attr attr = {0};
    attr.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
    attr.insns     = (uint64_t)(uintptr_t)insns;
    attr.insn_cnt  = insn_cnt;
    attr.license   = (uint64_t)(uintptr_t)"GPL";
    strncpy(attr.prog_name, "device_filter", sizeof(attr.prog_name) - 1);

    /* First attempt — normal load */
    int prog_fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd >= 0)
        return prog_fd;

    /* Retry with verifier log for diagnostics */
    int saved_errno = errno;
    char log_buf[65536] = {0};
    attr.log_buf   = (uint64_t)(uintptr_t)log_buf;
    attr.log_size  = sizeof(log_buf);
    attr.log_level = 1;

    prog_fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        fprintf(stderr, "BPF_PROG_LOAD failed: %s\n", strerror(saved_errno));
        if (log_buf[0] != '\0')
            fprintf(stderr, "Verifier log:\n%s\n", log_buf);
        return -1;
    }

    return prog_fd;
}

/* ── Attach BPF program to cgroup ─────────────────────────────────────── */

static int attach_prog(const char *cgroup_path, int prog_fd)
{
    int cgroup_fd = open(cgroup_path, O_DIRECTORY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        fprintf(stderr, "open cgroup '%s': %s\n", cgroup_path, strerror(errno));
        return -1;
    }

    union bpf_attr attr = {0};
    attr.attach_type   = BPF_CGROUP_DEVICE;
    attr.target_fd     = cgroup_fd;
    attr.attach_bpf_fd = prog_fd;

    if (sys_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) < 0) {
        fprintf(stderr, "BPF_PROG_ATTACH to '%s': %s\n",
                cgroup_path, strerror(errno));
        close(cgroup_fd);
        return -1;
    }

    fprintf(stderr, "BPF program attached to cgroup '%s'\n", cgroup_path);
    close(cgroup_fd);
    return 0;
}

/* ── Move this process into the cgroup ────────────────────────────────── */

static int move_to_cgroup(const char *cgroup_path)
{
    char procs_path[4096];
    int n = snprintf(procs_path, sizeof(procs_path),
                     "%s/cgroup.procs", cgroup_path);
    if (n < 0 || (size_t)n >= sizeof(procs_path)) {
        fprintf(stderr, "cgroup path too long: %s\n", cgroup_path);
        return -1;
    }

    int fd = open(procs_path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open '%s': %s\n", procs_path, strerror(errno));
        return -1;
    }

    /* Write our PID */
    dprintf(fd, "%d\n", getpid());
    close(fd);
    return 0;
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cgroup-path> [command...]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Loads the compiled BPF_PROG_TYPE_CGROUP_DEVICE "
                "program and attaches it\n");
        fprintf(stderr, "to the given cgroup.  If a command is specified, "
                "this process moves into\n");
        fprintf(stderr, "the cgroup first, then exec's the command under "
                "device filtering.\n");
        return 1;
    }

    const char *cgroup_path = argv[1];

    /* ── Metadata ─────────────────────────────────────────────────── */
    fprintf(stderr, "=== bpf-load ===\n");
    fprintf(stderr, "Source:       %s\n", policy_source);
    fprintf(stderr, "Clang:        %s\n", policy_clang);
    fprintf(stderr, "Source SHA256: %s\n", policy_sha256[0] ? policy_sha256 : "(none)");
    fprintf(stderr, "Instructions: %zu\n", policy_insns_cnt);
    fprintf(stderr, "Maps:         %zu\n", policy_maps_count);
    fprintf(stderr, "\n");

    /* ── Adjust memlock limit ──────────────────────────────────────── */
    adjust_memlock();

    /* ── Create maps ───────────────────────────────────────────────── */
    if (policy_maps_count > 0) {
        if (create_maps() < 0) {
            close_maps();
            return 1;
        }
    }

    /* ── Copy instructions into writable buffer ────────────────────── */
    uint8_t *prog = malloc(policy_insns_len);
    if (prog == NULL) {
        fprintf(stderr, "malloc(%zu) failed\n", policy_insns_len);
        close_maps();
        return 1;
    }
    memcpy(prog, policy_insns, policy_insns_len);

    /* ── Patch map fds ─────────────────────────────────────────────── */
    patch_map_fds(prog);

    /* ── Load BPF program ──────────────────────────────────────────── */
    int prog_fd = load_prog(prog, policy_insns_cnt);
    free(prog);
    if (prog_fd < 0) {
        close_maps();
        return 1;
    }
    fprintf(stderr, "BPF program loaded (fd=%d)\n", prog_fd);

    /* ── Attach to cgroup ──────────────────────────────────────────── */
    if (attach_prog(cgroup_path, prog_fd) < 0) {
        close(prog_fd);
        close_maps();
        return 1;
    }

    /* ── Optionally move to cgroup and exec command ───────────────── */
    if (argc > 2) {
        if (move_to_cgroup(cgroup_path) < 0) {
            close(prog_fd);
            close_maps();
            return 1;
        }
        execvp(argv[2], &argv[2]);
        perror("execvp");
        close(prog_fd);
        close_maps();
        return 1;
    }

    /* Maps and program stay pinned as long as they are referenced.
       We exit, but the program remains attached to the cgroup. */
    return 0;
}
