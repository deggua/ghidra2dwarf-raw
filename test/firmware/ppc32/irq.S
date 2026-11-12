/*
 * PPC32 exception vectors and handlers for the interrupt tests (603e /
 * MPC8245 style, MSR[IP]=1 so vectors live at 0xfff00000 + offset).
 *
 *   0x700 program check : "b prog_entry" stub (NOT a Ghidra entry point;
 *                         tagged INTERRUPT by the test setup)
 *   0x900 decrementer   : nops + "b dec_entry" (entry point at a vector)
 *   0xc00 system call   : complete handler in the vector (ends in rfi)
 *
 * The handlers build a typical exception frame on the interrupted stack:
 *   0(r1) back chain, 4(r1) LR save word for the C callee,
 *   8 r0, 12 SRR0, 16 SRR1, 20 LR, 24 CR, 28 CTR, 32 XER, 36.. r3-r12
 */

#define FRAME 96

    .macro SAVE_FRAME
    stwu    r1, -FRAME(r1)
    stw     r0, 8(r1)
    mfsrr0  r0
    stw     r0, 12(r1)
    mfsrr1  r0
    stw     r0, 16(r1)
    mflr    r0
    stw     r0, 20(r1)
    mfcr    r0
    stw     r0, 24(r1)
    mfctr   r0
    stw     r0, 28(r1)
    mfxer   r0
    stw     r0, 32(r1)
    stw     r3, 36(r1)
    stw     r4, 40(r1)
    stw     r5, 44(r1)
    stw     r6, 48(r1)
    stw     r7, 52(r1)
    stw     r8, 56(r1)
    stw     r9, 60(r1)
    stw     r10, 64(r1)
    stw     r11, 68(r1)
    stw     r12, 72(r1)
    .endm

    .macro RESTORE_FRAME_RFI
    lwz     r12, 72(r1)
    lwz     r11, 68(r1)
    lwz     r10, 64(r1)
    lwz     r9, 60(r1)
    lwz     r8, 56(r1)
    lwz     r7, 52(r1)
    lwz     r6, 48(r1)
    lwz     r5, 44(r1)
    lwz     r4, 40(r1)
    lwz     r3, 36(r1)
    lwz     r0, 32(r1)
    mtxer   r0
    lwz     r0, 28(r1)
    mtctr   r0
    lwz     r0, 24(r1)
    mtcr    r0
    lwz     r0, 20(r1)
    mtlr    r0
    lwz     r0, 16(r1)
    mtsrr1  r0
    lwz     r0, 12(r1)
    mtsrr0  r0
    lwz     r0, 8(r1)
    addi    r1, r1, FRAME
    rfi
    .endm

/* ---- vectors -------------------------------------------------------- */

    /* Two vectors leading into ordinary functions, which must not become
       interrupt handlers (they never fire in the test): */
    .section .vec.300, "ax"
    .globl dsi_vector
    .type dsi_vector, @function
dsi_vector:                     /* calls a no-return function C code calls too */
    li      r3, 0x300
    bl      irq_fatal
    .size dsi_vector, . - dsi_vector

    .section .vec.600, "ax"
    .globl align_vector
    .type align_vector, @function
align_vector:                   /* branches to a C function normal code calls */
    li      r3, 0x600
    b       shape_probe
    .size align_vector, . - align_vector

    .section .vec.700, "ax"
    .globl prog_vector
    .type prog_vector, @function
prog_vector:
    b       prog_entry
    .size prog_vector, . - prog_vector

    .section .vec.900, "ax"
    .globl dec_vector
    .type dec_vector, @function
dec_vector:
    nop
    nop
    nop
    b       dec_entry
    .size dec_vector, . - dec_vector

    .section .vec.c00, "ax"
    .globl sc_vector
    .type sc_vector, @function
sc_vector:
    SAVE_FRAME
    /* r3/r4 still hold the syscall arguments */
    bl      syscall_handler
    stw     r3, 36(r1)          /* return value -> interrupted r3 */
    RESTORE_FRAME_RFI
    .size sc_vector, . - sc_vector

/* ---- handlers outside the vector area ------------------------------- */

    .text
    /* No rfi of its own: leaves through the shared irq_exit, so it is only
       recognized as a handler because the (INTERRUPT-tagged) vector stub
       branches to it. */
    .globl prog_entry
    .type prog_entry, @function
prog_entry:
    SAVE_FRAME
    lwz     r3, 12(r1)          /* faulting PC */
    bl      program_check
    lwz     r3, 12(r1)          /* skip the trap instruction */
    addi    r3, r3, 4           /* (not r0: "addi rD,r0,x" means rD = x) */
    stw     r3, 12(r1)
    b       irq_exit
    .size prog_entry, . - prog_entry

    .globl irq_exit
    .type irq_exit, @function
irq_exit:
    RESTORE_FRAME_RFI
    .size irq_exit, . - irq_exit

    .globl dec_entry
    .type dec_entry, @function
dec_entry:
    SAVE_FRAME
    bl      timer_tick
    lis     r0, 0
    ori     r0, r0, 20000
    mtdec   r0                  /* re-arm */
    RESTORE_FRAME_RFI
    .size dec_entry, . - dec_entry

/* ---- helpers called from C ------------------------------------------ */

    .globl irq_fatal
    .type irq_fatal, @function
irq_fatal:                      /* void irq_fatal(int code): never returns */
    b       irq_fatal
    .size irq_fatal, . - irq_fatal

    .globl msr_keep
    .type msr_keep, @function
msr_keep:                       /* void msr_keep(void): rewrites the MSR, */
    mfmsr   r3                  /* returning to the caller with rfi */
    mflr    r4
    mtsrr0  r4
    mtsrr1  r3
    rfi
    .size msr_keep, . - msr_keep

    .globl do_syscall
    .type do_syscall, @function
do_syscall:                     /* int do_syscall(int num, int arg) */
    sc
    blr
    .size do_syscall, . - do_syscall

    .globl trap_now
    .type trap_now, @function
trap_now:
    trap
    blr
    .size trap_now, . - trap_now

    .globl irq_enable
    .type irq_enable, @function
irq_enable:                     /* void irq_enable(uint32_t dec) */
    mtdec   r3
    mfmsr   r4
    ori     r4, r4, 0x8000      /* MSR[EE] */
    mtmsr   r4
    blr
    .size irq_enable, . - irq_enable

    .globl irq_disable
    .type irq_disable, @function
irq_disable:
    mfmsr   r4
    rlwinm  r4, r4, 0, 17, 15   /* clear MSR[EE] */
    mtmsr   r4
    blr
    .size irq_disable, . - irq_disable

/* ---- shapes from the adversarial review ------------------------------ */

/* Out-of-line register save/restore helpers as GCC -Os -mno-multiple (and
   other compilers) use them: r11 points at the top of the frame. */
    .globl _savegpr_29
    .type _savegpr_29, @function
_savegpr_29:
    stw     r29, -12(r11)
    stw     r30, -8(r11)
    stw     r31, -4(r11)
    blr
    .size _savegpr_29, . - _savegpr_29

    .globl _restgpr_29_x
    .type _restgpr_29_x, @function
_restgpr_29_x:
    lwz     r0, 4(r11)
    lwz     r29, -12(r11)
    lwz     r30, -8(r11)
    lwz     r31, -4(r11)
    mtlr    r0
    mr      r1, r11
    blr
    .size _restgpr_29_x, . - _restgpr_29_x

    /* int shape_os(int a, int b, int c): saves r29-r31 through the helper,
       keeps its arguments there across a call */
    .globl shape_os
    .type shape_os, @function
shape_os:
    stwu    r1, -32(r1)
    mflr    r0
    addi    r11, r1, 32
    bl      _savegpr_29
    stw     r0, 36(r1)
    mr      r31, r3
    mr      r30, r4
    mr      r29, r5
    bl      shape_probe
    add     r3, r31, r30
    add     r3, r3, r29
    addi    r11, r1, 32
    b       _restgpr_29_x
    .size shape_os, . - shape_os

    /* int early_init(int v): boot-code style, no stack frame: the return
       address is parked in r30 (whose own value goes to a global) */
    .globl early_init
    .type early_init, @function
early_init:
    lis     r9, g_saved_r30@ha
    stw     r30, g_saved_r30@l(r9)
    mflr    r30
    bl      shape_probe
    addi    r3, r3, 1
    bl      shape_probe
    mtlr    r30
    lis     r9, g_saved_r30@ha
    lwz     r30, g_saved_r30@l(r9)
    blr
    .size early_init, . - early_init
