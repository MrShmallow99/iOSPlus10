#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "preserve_payload.h"

static void make(unsigned char *buffer)
{
    memset(buffer, 0, 1024);
    struct pp_payload *p = (struct pp_payload *)buffer;
    memcpy(p->magic, "NEGRONIX", 8);
    p->version = 1; p->nsegs = 1;
    p->virt_base = UINT64_C(0xfffffff000000000);
    p->entry_va = p->virt_base + 0x4000;
    p->kernel_end = p->virt_base + 0x8000;
    p->phys_base = UINT64_C(0x840000000); p->mem_size = UINT64_C(0xc0000000);
    p->adt_off = 736; p->adt_size = 16;
    strcpy(p->cmdline, "rd=md0 ufsrw=0 negronilog=0");
    p->segs[0] = (struct pp_segment){ p->entry_va, 0x4000, 720, 8 };
}

int main(int argc, char **argv)
{
    _Alignas(8) unsigned char buffer[3072];
    struct pp_payload *p = (struct pp_payload *)buffer;
    struct pp_layout layout;
    make(buffer);
    assert(pp_validate(buffer, 1024, 0x90000000, 0x90000400, &layout));
    for (unsigned i = 0; i < sizeof(struct pp_payload); i++)
        assert(!pp_validate(buffer, i, 0x90000000, 0x90000400, NULL));
    p->nsegs = UINT32_MAX;
    assert(!pp_validate(buffer, 1024, 0x90000000, 0x90000400, NULL));
    make(buffer); p->adt_off = UINT64_MAX - 7;
    assert(!pp_validate(buffer, 1024, 0x90000000, 0x90000400, NULL));
    make(buffer); p->segs[0].file_off = 1000;
    assert(!pp_validate(buffer, 1024, 0x90000000, 0x90000400, NULL));
    make(buffer); p->segs[0].vmaddr = UINT64_MAX - 7;
    assert(!pp_validate(buffer, 1024, 0x90000000, 0x90000400, NULL));
    make(buffer); p->entry_va = p->virt_base;
    assert(!pp_validate(buffer, 1024, 0x90000000, 0x90000400, NULL));
    make(buffer); p->nsegs = 2; p->adt_off = 784;
    p->segs[0].file_off = 760; p->segs[1] = p->segs[0]; p->segs[1].file_off = 768;
    assert(!pp_validate(buffer, 1024, 0x90000000, 0x90000400, NULL));
    make(buffer); strcpy(p->cmdline, "rd=md0 ufsrw=1 negronilog=0");
    assert(!pp_validate(buffer, 1024, 0x90000000, 0x90000400, NULL));
    make(buffer); strcat(p->cmdline, " rd=ufsroot0");
    assert(!pp_validate(buffer, 1024, 0x90000000, 0x90000400, NULL));
    make(buffer);
    assert(!pp_validate(buffer, 1024, UINT64_C(0x840000000), UINT64_C(0x840000400), NULL));
    memmove(buffer + 1024, buffer, 1024); memset(buffer, 0, 1024);
    assert(pp_find(buffer, 2048, 0x90000000, &layout) == (void *)(buffer + 1024));
    memcpy(buffer + 2048, buffer + 1024, 1024);
    assert(!pp_find(buffer, sizeof(buffer), 0x90000000, NULL));
    assert(!pp_find(buffer, UINT64_MAX, 0x90000000, NULL));
    /* Exercise malformed scalar headers with ASan/UBSan enabled by the runner. */
    uint32_t random = 12345;
    for (unsigned i = 0; i < 10000; i++) {
        make(buffer);
        for (unsigned j = 0; j < 8; j++) {
            random = random * 1664525u + 1013904223u;
            buffer[8 + random % (sizeof(struct pp_payload) - 8)] ^= (unsigned char)(random >> 24);
        }
        (void)pp_validate(buffer, 1024, 0x90000000, 0x90000400, NULL);
    }
    if (argc == 2) {
        FILE *file = fopen(argv[1], "rb"); assert(file);
        assert(fseek(file, 0, SEEK_END) == 0); long length = ftell(file); assert(length > 0);
        rewind(file); void *data = malloc((size_t)length); assert(data);
        assert(fread(data, 1, (size_t)length, file) == (size_t)length); fclose(file);
        assert(pp_find(data, (uint64_t)length, 0x90000000, &layout));
        free(data);
        puts("PASS: actual RAM-root payload accepted by runtime C validator");
    }
    puts("PASS: truncated, overflowing, unsafe, overlapping-source and ambiguous payloads rejected");
    return 0;
}
