/* PPC64 ELFv2 entry: compute the TOC pointer, make a frame with a NULL back
   chain, call _cstart (never returns). */
    .abiversion 2
    .text
    .globl _reset
    .type _reset, @function
_reset:
    bcl     20, 31, 1f
1:  mflr    12
    addis   2, 12, (.TOC. - 1b)@ha
    addi    2, 2, (.TOC. - 1b)@l
    li      0, 0
    stdu    1, -64(1)
    std     0, 0(1)
    bl      _cstart
    nop
2:  b       2b
    .size _reset, . - _reset
