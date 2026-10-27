/* SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> */
/* SPDX-License-Identifier: MIT */
.section .boot.text,"ax",@progbits
.option norvc
.global atomic_boot_entry
atomic_boot_entry:
  la t0, atomic_init_begin
  la t1, atomic_init_end
1:
  beq t0, t1, 2f
  lw t2, 0(t0)
  lw t3, 4(t0)
  sw t3, 0(t2)
  addi t0, t0, 8
  j 1b
2:
  j rvtest_entry_point
.balign 64
