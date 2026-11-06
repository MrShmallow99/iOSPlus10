#include <assert.h>
#include <stdio.h>
#include "negroni_ufs_preserve.h"

int main(void)
{
    unsigned char cdb[16] = {0};
    assert(!negroni_ufs_preserve_allows(NULL, 0, 0, 0));
    assert(!negroni_ufs_preserve_allows(cdb, 0, 0, 0));
    assert(negroni_ufs_preserve_allows(cdb, 6, 0, 0));
    for (unsigned op = 0; op < 256; op++) {
        cdb[0] = (unsigned char)op;
        assert(!negroni_ufs_preserve_allows(cdb, 6, 0, 1));
        assert(!negroni_ufs_preserve_allows(cdb, 10, 4096, 1));
        if (op != 0) {
            assert(!negroni_ufs_preserve_allows(cdb, 6, 0, 0));
        }
        assert(!negroni_ufs_preserve_allows(cdb, 10, 4096, 0));
    }
    cdb[0] = 0x1b;
    cdb[4] = 0x10;
    assert(negroni_ufs_preserve_allows(cdb, 6, 0, 0));
    cdb[4] = 0x20;
    assert(!negroni_ufs_preserve_allows(cdb, 6, 0, 0));
    cdb[4] = 0;
    cdb[0] = 0x28;
    cdb[8] = 1;
    assert(negroni_ufs_preserve_allows(cdb, 10, 4096, 0));
    assert(!negroni_ufs_preserve_allows(cdb, 9, 4096, 0));
    assert(!negroni_ufs_preserve_allows(cdb, 10, 512, 0));
    assert(!negroni_ufs_preserve_allows(cdb, 10, 0, 0));
    cdb[7] = 1;
    cdb[8] = 0;
    assert(negroni_ufs_preserve_allows(cdb, 10, 1u << 20, 0));
    cdb[8] = 1;
    assert(!negroni_ufs_preserve_allows(cdb, 10, (1u << 20) + 4096, 0));
    cdb[7] = 0;
    cdb[8] = 1;
    cdb[9] = 1;
    assert(!negroni_ufs_preserve_allows(cdb, 10, 4096, 0));
    puts("PASS: UFS command policy; all data-out and unknown commands rejected");
    return 0;
}
