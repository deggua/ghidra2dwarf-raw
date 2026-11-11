/* See ppc32/edge_asm.S. ELFv1: functions are .opd descriptors. */
#define FUNC(name) \
    .section ".opd", "aw"; .align 3; .globl name; .type name, @function; \
name: .quad .L.name, .TOC.@tocbase, 0; .size name, 24; .previous; .L.name:

    .abiversion 1
    .text
FUNC(split_func)
    li      3, 7
    b       .L.split_tail

FUNC(asm_between)
    li      3, 1
    blr

FUNC(split_tail)
    addi    3, 3, 1
    blr

    .globl bad_bytes
    .type bad_bytes, @object
bad_bytes:
    .long   0
    .long   0
    .size bad_bytes, . - bad_bytes
