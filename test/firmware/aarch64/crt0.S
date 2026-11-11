/* AArch64 entry. */
    .text
    .globl _reset
    .type _reset, %function
_reset:
    mov     x29, xzr
    mov     x30, xzr
    bl      _cstart
1:  b       1b
    .size _reset, . - _reset
