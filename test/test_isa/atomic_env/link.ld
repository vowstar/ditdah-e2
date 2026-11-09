/* SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> */
/* SPDX-License-Identifier: MIT */
OUTPUT_ARCH(riscv)
ENTRY(atomic_boot_entry)
INCLUDE memory.ld
PHDRS { @PROGRAM_HEADERS@ }
SECTIONS
{
  .text : { KEEP(*(.boot.text)) *(.text.init) *(.text .text.*) } > ROM :code
  .atomic_init : { KEEP(*(.atomic_init)) } > ROM :init
  .data : { *(.data .data.*) *(.rodata .rodata.*) } > SRAM :data
  .signature : { *(.signature) } > SRAM :data
  .tohost : { *(.tohost) } > SRAM :data
  .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) . = ALIGN(4); } > SRAM :data
}
