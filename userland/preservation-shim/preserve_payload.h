/* Bounded NEGRONIX locator/validator for this preservation RAM-root profile. */
#ifndef PRESERVE_PAYLOAD_H
#define PRESERVE_PAYLOAD_H
#include <stdint.h>
#include <stddef.h>

struct pp_segment { uint64_t vmaddr, vmsize, file_off, file_size; };
struct pp_payload {
    char magic[8];
    uint32_t version, nsegs;
    uint64_t virt_base, entry_va, adt_off, adt_size, kernel_end;
    uint64_t phys_base, mem_size;
    char cmdline[608];
    struct pp_segment segs[];
};
struct pp_layout { uint64_t adt_pa, args_pa, top, payload_bytes; };
_Static_assert(sizeof(struct pp_payload) == 0x2a8, "payload ABI");
_Static_assert(sizeof(struct pp_segment) == 32, "segment ABI");

static inline int pp_equal(const char *p, size_t n, const char *s)
{
    size_t i = 0;
    while (s[i]) { if (i >= n || p[i] != s[i]) return 0; i++; }
    return i == n;
}

static inline int pp_prefix(const char *p, size_t n, const char *s)
{
    size_t i = 0;
    while (s[i]) { if (i >= n || p[i] != s[i]) return 0; i++; }
    return 1;
}

static inline int pp_arguments(const char line[608])
{
    size_t length = 0, at = 0;
    unsigned root = 0, writes = 0, log = 0;
    while (length < 608 && line[length]) length++;
    if (length == 608) return 0;
    while (at < length) {
        while (at < length && line[at] == ' ') at++;
        size_t start = at;
        while (at < length && line[at] != ' ') at++;
        size_t n = at - start;
        if (pp_prefix(line + start, n, "rd=")) {
            if (!pp_equal(line + start, n, "rd=md0")) return 0;
            root++;
        }
        if (pp_prefix(line + start, n, "ufsrw=")) {
            if (!pp_equal(line + start, n, "ufsrw=0")) return 0;
            writes++;
        }
        if (pp_prefix(line + start, n, "negronilog=")) {
            if (!pp_equal(line + start, n, "negronilog=0")) return 0;
            log++;
        }
        if (pp_prefix(line + start, n, "ufsroot=")) return 0;
    }
    return root == 1 && writes == 1 && log == 1;
}

static inline int pp_validate(const void *buffer, uint64_t available,
    uint64_t source_start, uint64_t source_end, struct pp_layout *result)
{
    if (!buffer || ((uintptr_t)buffer & 7) || available < sizeof(struct pp_payload) || available > UINT64_C(0x20000000) ||
        source_end < source_start || available > source_end - source_start) return 0;
    const struct pp_payload *p = buffer;
    if (!pp_equal(p->magic, 8, "NEGRONIX") || p->version != 1 || p->nsegs == 0 || p->nsegs > 32) return 0;
    /* This profile uses a measured subset of this phone's high System RAM. */
    if (p->phys_base != UINT64_C(0x840000000) || p->mem_size != UINT64_C(0xc0000000)) return 0;
    uint64_t end = p->phys_base + p->mem_size;
    if (source_start < end && p->phys_base < source_end) return 0;
    if (p->virt_base > UINT64_MAX - p->mem_size || (p->virt_base & UINT64_C(0x1ffffff)) || (p->entry_va & 3) || p->entry_va < p->virt_base ||
        p->kernel_end < p->virt_base || p->kernel_end - p->virt_base > p->mem_size ||
        (p->kernel_end & UINT64_C(0x3fff))) return 0;
    uint64_t header = sizeof(*p) + p->nsegs * sizeof(struct pp_segment);
    if (header > available || (p->adt_off & 7) || p->adt_off < header || p->adt_off > available ||
        p->adt_size == 0 || p->adt_size > (1u << 20)) return 0;
    uint64_t tree_read = (p->adt_size + 7) & ~UINT64_C(7);
    if (tree_read > available - p->adt_off || !pp_arguments(p->cmdline)) return 0;
    unsigned entry_found = 0;
    for (uint32_t i = 0; i < p->nsegs; i++) {
        const struct pp_segment *s = &p->segs[i];
        if (s->vmaddr < p->virt_base || (s->vmaddr & 7) || s->vmsize == 0 || (s->vmsize & 7) ||
            s->vmaddr - p->virt_base > p->mem_size || s->vmsize > p->mem_size - (s->vmaddr - p->virt_base) ||
            s->file_size > s->vmsize || (s->file_off & 7) || s->file_off < header || s->file_off > p->adt_off) return 0;
        uint64_t file_read = (s->file_size + 7) & ~UINT64_C(7);
        if (file_read > s->vmsize || file_read > p->adt_off - s->file_off ||
            s->vmaddr > p->kernel_end || s->vmsize > p->kernel_end - s->vmaddr) return 0;
        if (p->entry_va >= s->vmaddr && p->entry_va - s->vmaddr < s->file_size) entry_found = 1;
        for (uint32_t j = 0; j < i; j++) {
            const struct pp_segment *old = &p->segs[j];
            if (s->vmaddr < old->vmaddr + old->vmsize && old->vmaddr < s->vmaddr + s->vmsize) return 0;
        }
    }
    if (!entry_found) return 0;
    uint64_t adt_pa = p->phys_base + (p->kernel_end - p->virt_base);
    if (adt_pa > end || tree_read > end - adt_pa) return 0;
    uint64_t args_pa = (adt_pa + p->adt_size + 0x3fff) & ~UINT64_C(0x3fff);
    if (args_pa > end || UINT64_C(0x4000) > end - args_pa) return 0;
    uint64_t bytes = (p->adt_off + p->adt_size + 15) & ~UINT64_C(15);
    if (bytes > available) return 0;
    if (result) {
        result->adt_pa = adt_pa; result->args_pa = args_pa;
        result->top = args_pa + 0x4000; result->payload_bytes = bytes;
    }
    return 1;
}

/* Locate one valid payload after a possible vendor ramdisk prefix. Reject ambiguity. */
static inline const struct pp_payload *pp_find(const void *buffer, uint64_t size,
    uint64_t source_start, struct pp_layout *result)
{
    if (!buffer || ((uintptr_t)buffer & 7) || (source_start & 7) || size < sizeof(struct pp_payload) ||
        size > UINT64_C(0x20000000) || source_start > UINT64_MAX - size) return NULL;
    const unsigned char *bytes = buffer;
    const struct pp_payload *found = NULL;
    struct pp_layout candidate;
    for (uint64_t at = 0; at <= size - sizeof(struct pp_payload); at += 8) {
        if (*(const uint64_t *)(bytes + at) != UINT64_C(0x58494e4f5247454e)) continue;
        if (!pp_validate(bytes + at, size - at, source_start, source_start + size, &candidate)) continue;
        if (found) return NULL;
        found = (const struct pp_payload *)(bytes + at);
        if (result) *result = candidate;
    }
    return found;
}
#endif
