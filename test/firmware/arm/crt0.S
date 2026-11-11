/* ARM / Thumb-2 entry. */
    .syntax unified
#ifdef __thumb__
    .thumb
#define FUNC(name) .globl name; .type name, %function; .thumb_func; name:
#else
    .arm
#define FUNC(name) .globl name; .type name, %function; name:
#endif
    .text
FUNC(_reset)
    mov     r7, #0
    mov     fp, #0
    bl      _cstart
1:  b       1b
    .size _reset, . - _reset
