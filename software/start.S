# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

.file "start.S"
.section .text.start, "ax", @progbits
.globl _start
.type _start, @function
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    la sp, __stack_top
    .option pop
    la t0, __bss_start
    la t1, __bss_end
1:
    beq t0, t1, 2f
    sw zero, 0(t0)
    addi t0, t0, 4
    j 1b
2:
    call main
.globl software_done
.type software_done, @function
software_done:
    j software_done
.size software_done, .-software_done
.size _start, .-_start
