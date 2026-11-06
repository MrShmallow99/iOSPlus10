/* Minimal preservation entry: no UEFI, UFS, SMP probes, or reset-reason writes. */
#include <stdint.h>
#include "console.h"
#include "loader.h"

static __attribute__((noreturn)) void stop(void)
{
    for (;;) __asm__ volatile("wfe");
}

void shim_main(uint64_t dtb)
{
    /* Existing board requirement: disable the inherited Gunyah watchdog. */
    register uint64_t x0 __asm__("x0") = 0x86000005;
    register uint64_t x1 __asm__("x1") = 2;
    register uint64_t x2 __asm__("x2") = 0;
    register uint64_t x3 __asm__("x3") = 0;
    __asm__ volatile("smc #0" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3) : :
        "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "cc", "memory");
    con_clear(RED);
    con_str("SHIM", "preservation RAM-root loader");
    con_str("LOADER", loader_boot(dtb));
    stop();
}

void secondary_main(uint64_t cpu)
{
    (void)cpu;
    stop();
}

void exc_handler(uint64_t slot, const uint64_t *registers)
{
    (void)registers;
    con_clear(BLUE);
    con_hex("EXCEPT", slot);
    stop();
}
