/* PPC64 ELFv1 entry. Functions are function descriptors in .opd
   (code address, TOC base, environment); the loader starts at the
   descriptor e_entry points to, loading r2 from it. */
#define FUNC(name) \
    .section ".opd", "aw"; .align 3; .globl name; .type name, @function; \
name: .quad .L.name, .TOC.@tocbase, 0; .size name, 24; .previous; .L.name:

    .abiversion 1
    .text
FUNC(_reset)
    li      0, 0
    stdu    1, -128(1)
    std     0, 0(1)
    bl      _cstart
    nop
1:  b       1b
