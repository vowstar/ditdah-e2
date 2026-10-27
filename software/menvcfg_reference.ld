/* SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> */
/* SPDX-License-Identifier: MIT */
OUTPUT_ARCH(riscv)
ENTRY(_start)
PHDRS { data PT_LOAD FLAGS(6); code PT_LOAD FLAGS(5); }
SECTIONS {
  . = 0x80000000;
  .text : { *(.text.start) *(.text*) } :code
  . = 0x20000000;
  .data : { *(.data*) } :data
  /DISCARD/ : { *(.comment) *(.riscv.attributes) }
}
