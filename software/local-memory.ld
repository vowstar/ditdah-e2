/* SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> */
/* SPDX-License-Identifier: MIT */
OUTPUT_ARCH(riscv)
ENTRY(_start)
INCLUDE memory.ld
PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}
SECTIONS
{
    .text :
    {
        KEEP(*(.text.start))
        *(.text .text.*)
        *(.rodata .rodata.*)
        . = ALIGN(4);
    } > ITCM :text
    .data :
    {
        *(.data .data.* .sdata .sdata.*)
        . = ALIGN(4);
    } > DTCM :data
    .bss (NOLOAD) :
    {
        __bss_start = .;
        *(.bss .bss.* .sbss .sbss.* COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > DTCM :data
    __global_pointer$ = ORIGIN(DTCM) + 0x800;
    __stack_top = (ORIGIN(DTCM) + LENGTH(DTCM)) & ~15;
    ASSERT(__bss_end <= __stack_top - 256, "Insufficient local stack space")
}
