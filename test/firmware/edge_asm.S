/*
 * Hand-written edge cases:
 *   split_func   a function whose body is non-contiguous: it branches over
 *                asm_between (a separate function) to its tail.
 *   bad_bytes    bytes that do not disassemble; the Ghidra setup creates a
 *                function there to exercise the "decompilation failed" path.
 */
    .text
    .globl split_func
    .type split_func, @function
split_func:
    li      r3, 7
    b       split_tail
    .size split_func, . - split_func

    .globl asm_between
    .type asm_between, @function
asm_between:
    li      r3, 1
    blr
    .size asm_between, . - asm_between

split_tail:
    addi    r3, r3, 1
    blr

    .globl bad_bytes
    .type bad_bytes, @object
bad_bytes:
    .long   0
    .long   0
    .size bad_bytes, . - bad_bytes
