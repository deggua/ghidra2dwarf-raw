/* See ppc32/edge_asm.S. */
    .abiversion 2
    .text
    .globl split_func
    .type split_func, @function
split_func:
    li      3, 7
    b       split_tail
    .size split_func, . - split_func

    .globl asm_between
    .type asm_between, @function
asm_between:
    li      3, 1
    blr
    .size asm_between, . - asm_between

    .globl split_tail
    .type split_tail, @function
split_tail:
    addi    3, 3, 1
    blr
    .size split_tail, . - split_tail

    .globl bad_bytes
    .type bad_bytes, @object
bad_bytes:
    .long   0
    .long   0
    .size bad_bytes, . - bad_bytes
