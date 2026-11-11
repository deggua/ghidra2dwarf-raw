/* See ppc32/edge_asm.S. Branches have delay slots. */
    .set noreorder
    .text
    .globl split_func
    .type split_func, @function
    .ent split_func
split_func:
    li      $v0, 7
    b       split_tail
    nop
    .end split_func
    .size split_func, . - split_func

    .globl asm_between
    .type asm_between, @function
    .ent asm_between
asm_between:
    jr      $ra
    li      $v0, 1
    .end asm_between
    .size asm_between, . - asm_between

    .globl split_tail
    .type split_tail, @function
    .ent split_tail
split_tail:
    jr      $ra
    addiu   $v0, $v0, 1
    .end split_tail
    .size split_tail, . - split_tail

    .globl bad_bytes
    .type bad_bytes, @object
bad_bytes:
    .word   0
    .word   0
    .size bad_bytes, . - bad_bytes
