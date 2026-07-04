#include "bpf_types.h"
#include "bpf_helpers.h"

/* Packed struct for the device hashmap key */
struct device_key {
    uint8_t  type;    /* 'b' = block, 'c' = char */
    uint32_t major;
    uint32_t minor;
} __attribute__((packed));

/* Define the BPF hash map in the .maps section.
   Clang recognizes this pattern and emits map relocation entries. */
struct {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
} devmap SEC(".maps") = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct device_key),
    .value_size  = 1,
    .max_entries = 1000,
};

/*
 * device_filter — BPF_PROG_TYPE_CGROUP_DEVICE program
 *
 * Return 1 to ALLOW, 0 to DENY the device access.
 *
 * Logic (matching snapd's `load_devcgroup_prog`):
 *   1. Extract {type, major, minor} from the cgroup_dev_ctx
 *   2. Decode access_type & 0xFFFF → 'b' or 'c'
 *   3. Unknown type → return 0 (deny)
 *   4. Look up exact {type, major, minor} in the hash map → found? return 1
 *   5. Retry with minor = 0xFFFFFFFF (wildcard) → found? return 1
 *   6. Otherwise return 0 (deny)
 */
SEC("cgroup/dev")
int device_filter(struct bpf_cgroup_dev_ctx *ctx)
{
    struct device_key key = {0};

    key.major = ctx->major;
    key.minor = ctx->minor;

    uint32_t dev_type = ctx->access_type & 0xFFFF;

    if (dev_type == BPF_DEVCG_DEV_BLOCK) {
        key.type = 'b';
    } else if (dev_type == BPF_DEVCG_DEV_CHAR) {
        key.type = 'c';
    } else {
        return 0;   /* unknown device type → deny */
    }

    /* Exact match lookup */
    if (bpf_map_lookup_elem(&devmap, &key))
        return 1;   /* allowed */

    /* Wildcard minor (0xFFFFFFFF = any minor) */
    key.minor = 0xFFFFFFFF;
    if (bpf_map_lookup_elem(&devmap, &key))
        return 1;   /* allowed via wildcard */

    return 0;   /* deny */
}
