/* MIPS (o32 and n64) entry: reserve an argument area, call _cstart. */
    .set noreorder
    .text
    .globl _reset
    .type _reset, @function
    .ent _reset
_reset:
    move    $fp, $zero
#if _MIPS_SIM == _ABI64
    daddiu  $sp, $sp, -32
#else
    addiu   $sp, $sp, -32
#endif
    jal     _cstart
    nop
1:  b       1b
    nop
    .end _reset
    .size _reset, . - _reset
