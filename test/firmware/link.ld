ENTRY(_reset)

MEMORY
{
    ROM (rx)  : ORIGIN = 0xfff00000, LENGTH = 1M
    RAM (rwx) : ORIGIN = 0x00100000, LENGTH = 7M
}

SECTIONS
{
    .vectors 0xfff00000 : {
        . = 0x100;
        KEEP(*(.reset))
    } > ROM

    .text : {
        *(.text .text.*)
    } > ROM

    .rodata : {
        *(.rodata .rodata.* .sdata2 .sdata2.* .sbss2 .sbss2.*)
    } > ROM

    .data : {
        . = ALIGN(4);
        __data_start = .;
        *(.data .data.* .sdata .sdata.*)
        . = ALIGN(4);
        __data_end = .;
    } > RAM AT > ROM
    __data_load = LOADADDR(.data);

    .bss (NOLOAD) : {
        . = ALIGN(4);
        __bss_start = .;
        *(.bss .bss.* .sbss .sbss.* COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > RAM

    __stack_top = 0x00800000;

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.gnu.attributes) }
}
