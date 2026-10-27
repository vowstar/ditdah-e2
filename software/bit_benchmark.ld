/* SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> */
/* SPDX-License-Identifier: MIT */

OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    ROM (rx) : ORIGIN = 0x00000000, LENGTH = 64K
    RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}

PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    .text __reset_vector :
    {
        __benchmark_text_start = .;
        KEEP(*(.text.start))
        . = ALIGN(4);
        __benchmark_code_start = .;
        KEEP(*(.text.benchmark))
        __benchmark_code_end = .;
        *(.text .text.*)
        __benchmark_text_end = .;
    } > ROM :text
    .rodata :
    {
        *(.rodata .rodata.*)
    } > ROM :text
    .data :
    {
        *(.data .data.* .sdata .sdata.*)
    } > RAM :data
    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        __bss_start = .;
        *(.bss .bss.* .sbss .sbss.* COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > RAM :data
    __global_pointer$ = ORIGIN(RAM) + 0x800;
    __stack_top = ORIGIN(RAM) + LENGTH(RAM);
    ASSERT(__bss_end <= __stack_top - 256, "Insufficient stack space")
}
