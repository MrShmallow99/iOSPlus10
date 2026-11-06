/* EMULATOR ONLY. Virtual EL3 monitor, never part of the phone Image.
 * Model just the Gunyah watchdog-disable return. Reject other SMC services.
 * DTB and shim addresses match emulate-ramroot.py's virtual handoff fixture.
 */
.text
.ifndef SHIM_ENTRY
.equ SHIM_ENTRY, 0xa8008000
.endif
.ifndef FDT_ADDRESS
.equ FDT_ADDRESS, 0xb0000000
.endif
.global _start
_start:
    msr daifset, #15
    /* Match QEMU's usual single-security-state interrupt model. Without this,
     * enabling EL3 leaves timer PPIs secure and the nonsecure kernel never ticks.
     * This touches only QEMU's virtual GIC, never the physical phone GIC. */
    ldr x1, =0x08000000
    ldr w2, [x1]
    orr w2, w2, #0x40             // GICD_CTLR.DS
    str w2, [x1]
    dsb sy
    mov x1, #15
    msr icc_sre_el3, x1
    isb
    adr x1, vectors
    msr vbar_el3, x1
    mov x1, #0x401                 // SCR_EL3.NS=1, RW=1: nonsecure AArch64
    msr scr_el3, x1
    mov x1, #0x3c5                 // EL1h, interrupts masked
    msr spsr_el3, x1
    ldr x1, =SHIM_ENTRY
    msr elr_el3, x1
    ldr x0, =FDT_ADDRESS
    isb
    eret
.balign 2048
vectors:
.rept 16
    b handle
    .space 124
.endr
handle:
    mrs x4, esr_el3
    lsr x4, x4, #26
    cmp x4, #0x17                 // SMC64
    b.ne halt
    ldr x4, =0x86000005
    cmp x0, x4
    b.ne unsupported
    cmp x1, #2                    // watchdog disable
    b.ne unsupported
    mov x0, #0
    eret
unsupported:
    mov x0, #-1
    eret
halt:
    wfe
    b halt
