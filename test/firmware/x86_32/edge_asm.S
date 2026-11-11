/* See ppc32/edge_asm.S. */
    .text
    .globl split_func
    .type split_func, @function
split_func:
    mov     $7, %eax
    jmp     split_tail
    .size split_func, . - split_func

    .globl asm_between
    .type asm_between, @function
asm_between:
    mov     $1, %eax
    ret
    .size asm_between, . - asm_between

    .globl split_tail
    .type split_tail, @function
split_tail:
    add     $1, %eax
    ret
    .size split_tail, . - split_tail

    .globl bad_bytes
    .type bad_bytes, @object
bad_bytes:
    .long   0
    .long   0
    .size bad_bytes, . - bad_bytes
