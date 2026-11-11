/* x86 entry: clear the frame pointer, align the stack, call _cstart. */
    .text
    .globl _reset
    .type _reset, @function
_reset:
    xor     %ebp, %ebp
    and     $-16, %rsp
    call    _cstart
1:  jmp     1b
    .size _reset, . - _reset
