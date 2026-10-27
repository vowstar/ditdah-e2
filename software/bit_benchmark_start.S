# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
.file "bit_benchmark_start.S"
.section .text.start, "ax", @progbits
.globl _start
.type _start, @function
_start:
    .option push
    .option norelax
    la sp, __stack_top
    la t0, __bss_start
    la t1, __bss_end
1:
    beq t0, t1, 2f
    sw zero, 0(t0)
    addi t0, t0, 4
    j 1b
2:
.globl benchmark_begin
benchmark_begin:
    call benchmark
.globl benchmark_end
benchmark_end:
    la t0, benchmark_return
    sw a0, 0(t0)
    j benchmark_done
    .option pop
.size _start, .-_start

.section .text.done, "ax", @progbits
.balign 4
.option push
.option norvc
.globl benchmark_done
.type benchmark_done, @function
benchmark_done:
    jal zero, benchmark_done
.size benchmark_done, .-benchmark_done
.option pop
