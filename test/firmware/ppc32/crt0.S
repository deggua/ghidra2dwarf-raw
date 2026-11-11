/*
 * Reset entry for the test firmware. The image is a raw ROM placed at
 * 0xfff00000; a classic 32-bit PowerPC (MSR[IP]=1) resets to 0xfff00100.
 * We run in real mode (MMU off), with RAM at 0.
 */
    .section .reset, "ax"
    .globl _reset
    .type _reset, @function
_reset:
    /* Enable the FPU (MSR[FP] = 0x2000) */
    mfmsr   r3
    ori     r3, r3, 0x2000
    mtmsr   r3
    isync

    /* Set up the stack with a NULL back-chain word */
    lis     r1, __stack_top@ha
    addi    r1, r1, __stack_top@l
    li      r0, 0
    stwu    r0, -16(r1)

    bl      _cstart
1:  b       1b
    .size _reset, . - _reset
