/* See ppc32/edge_asm.S. */
    .syntax unified
#ifdef __thumb__
    .thumb
#define FUNC(name) .globl name; .type name, %function; .thumb_func; name:
#else
    .arm
#define FUNC(name) .globl name; .type name, %function; name:
#endif
    .text
FUNC(split_func)
    mov     r0, #7
    b       split_tail
    .size split_func, . - split_func

FUNC(asm_between)
    mov     r0, #1
    bx      lr
    .size asm_between, . - asm_between

FUNC(split_tail)
    add     r0, r0, #1
    bx      lr
    .size split_tail, . - split_tail

    .globl bad_bytes
    .type bad_bytes, %object
    .p2align 2
bad_bytes:
    .word   0
    .word   0
    .size bad_bytes, . - bad_bytes
