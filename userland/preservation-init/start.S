// Minimal RAM-root PID 1. No libraries, mounts, partition access, or reboot calls.
// BSD syscall numbers match xnu-8796.141.3/bsd/kern/syscalls.master.
.section __TEXT,__text,regular,pure_instructions
.globl _start
.p2align 2
_start:
    adrp x0, console_path@PAGE
    add x0, x0, console_path@PAGEOFF
    mov x1, #1                  // O_WRONLY, never O_CREAT
    mov x2, #0
    mov x16, #5                 // open
    svc #0x80
    b.cs 1f
    mov x19, x0
    adrp x1, ready_message@PAGE
    add x1, x1, ready_message@PAGEOFF
    mov x2, #(ready_message_end - ready_message)
    mov x16, #4                 // write to /dev/console only
    svc #0x80
1:
    sub sp, sp, #16
2:
    mov x5, #1
    str x5, [sp]
    str xzr, [sp, #8]           // timeval: one second, zero microseconds
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, sp
    mov x16, #93                // select(0, NULL, NULL, NULL, &timeout)
    svc #0x80
    b 2b

.section __TEXT,__cstring,cstring_literals
console_path:
    .asciz "/dev/console"
ready_message:
    .ascii "PRESERVE RAM ROOT: PID 1 reached.\n"
ready_message_end:
