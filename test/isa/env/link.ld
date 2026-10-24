/* SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> */
/* SPDX-License-Identifier: MIT */
OUTPUT_ARCH(riscv)
ENTRY(rvtest_entry_point)
MEMORY { ram (rwx) : ORIGIN = 0x80000000, LENGTH = 4M }
PHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS
{
  .text : { *(.text.init) *(.text .text.*) } > ram :code
  . = ALIGN(4096);
  .data : { *(.data .data.*) *(.rodata .rodata.*) } > ram :data
  .signature : { *(.signature) } > ram :data
  .tohost : { *(.tohost) } > ram :data
  .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } > ram :data
}
