/* See ppc32/edge_asm.S. */
    .text
    .globl split_func
    .type split_func, %function
split_func:
    mov     w0, #7
    b       split_tail
    .size split_func, . - split_func

    .globl asm_between
    .type asm_between, %function
asm_between:
    mov     w0, #1
    ret
    .size asm_between, . - asm_between

    .globl split_tail
    .type split_tail, %function
split_tail:
    add     w0, w0, #1
    ret
    .size split_tail, . - split_tail

    .globl bad_bytes
    .type bad_bytes, %object
    .p2align 2
bad_bytes:
    .word   0
    .word   0
    .size bad_bytes, . - bad_bytes
