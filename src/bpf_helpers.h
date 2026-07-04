/*
 * BPF helper function declarations for clang -target bpf.
 *
 * These are minimal declarations that let clang generate the correct
 * BPF_CALL instructions.  The function number (cast as the function
 * pointer value) tells clang which BPF helper to invoke.
 *
 * Not needed by the runtime loader — only by policy.c (the BPF program).
 */

#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

/* Section attribute for BPF program / map placement */
#define SEC(name) __attribute__((section(name), used))

/* BPF_FUNC_map_lookup_elem (1)
 *   void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
 *
 * Returns a pointer to the value stored in the map at key, or NULL if
 * no entry exists.
 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)1;

#endif /* BPF_HELPERS_H */
