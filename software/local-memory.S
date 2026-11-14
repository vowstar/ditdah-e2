// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "platform.h"
.option norvc
.section .text.start
.globl _start
_start:
    la sp, __stack_top
    la t0, initialized_word
    lw t1, 0(t0)
    li t2, 0x13579bdf
    bne t1, t2, failed
    la t0, zero_word
    lw t1, 0(t0)
    bnez t1, failed
    li t1, 0x11223344
    sw t1, 0(t0)
    li t1, 0xaa
    sb t1, 1(t0)
    lhu t1, 0(t0)
    li t2, 0xaa44
    bne t1, t2, failed
    li t1, 0xbbcc
    sh t1, 2(t0)
    lw t1, 0(t0)
    li t2, 0xbbccaa44
    bne t1, t2, failed
    li t0, DITDAH_DTCM_BASE + DITDAH_DTCM_SIZE - 4
    sw t2, 0(t0)
    lw t1, 0(t0)
    bne t1, t2, failed
    li t0, DITDAH_SRAM_BASE
    sw t2, 0(t0)
    lw t1, 0(t0)
    bne t1, t2, failed
    call code_word
    li t1, 1
    bne a0, t1, failed
    la t0, code_word
    li t1, 0x00700513
    sw t1, 0(t0)
    fence.i
    call code_word
    li t1, 7
    bne a0, t1, failed
    la t0, data_code
    li t1, 0x00900513
    sw t1, 0(t0)
    li t1, 0x00008067
    sw t1, 4(t0)
    fence.i
    jalr ra, t0, 0
    li t1, 9
    bne a0, t1, failed
    li t0, DITDAH_TIMER_BASE + 16
    sw zero, 0(t0)
    lw t1, 0(t0)
    bnez t1, failed
    li t0, DITDAH_CONSOLE_BASE
    li t1, 76
    sw t1, 0(t0)
    li t1, 10
    sw t1, 0(t0)
.globl software_done
software_done:
    j software_done
failed:
    li t0, DITDAH_CONSOLE_BASE
    li t1, 70
    sw t1, 0(t0)
1:
    j 1b
.section .text
.align 2
code_word:
    addi a0, zero, 1
    ret
.section .data
.globl initialized_word
initialized_word:
    .word 0x13579bdf
.section .bss
.align 2
zero_word:
    .space 4
data_code:
    .space 8
