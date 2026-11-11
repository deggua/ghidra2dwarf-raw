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
    .globl prog_entry
    .type prog_entry, @function
prog_entry:
    SAVE_FRAME
    lwz     r3, 12(r1)          /* faulting PC */
    bl      program_check
    lwz     r3, 12(r1)          /* skip the trap instruction */
    addi    r3, r3, 4           /* (not r0: "addi rD,r0,x" means rD = x) */
    stw     r3, 12(r1)
    RESTORE_FRAME_RFI
    .size prog_entry, . - prog_entry

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
