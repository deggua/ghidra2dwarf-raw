/* PPC64 ELFv2 entry: load the TOC pointer (absolute: the image is linked at
   a fixed address), make a frame with a NULL back chain, call _cstart. */
    .abiversion 2
    .text
    .globl _reset
    .type _reset, @function
_reset:
    lis     2, .TOC.@highest
    ori     2, 2, .TOC.@higher
    sldi    2, 2, 32
    oris    2, 2, .TOC.@h
    ori     2, 2, .TOC.@l
    li      0, 0
    stdu    1, -64(1)
    std     0, 0(1)
    bl      _cstart
    nop
1:  b       1b
    .size _reset, . - _reset
