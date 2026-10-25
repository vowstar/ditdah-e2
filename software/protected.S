# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

.file "protected.S"
.option push
.option norvc
.section .text, "ax", @progbits
.balign 4
.globl main
main:
    la t0, protected_handler
    csrw mtvec, t0
    csrw mie, zero
    la t0, protected_word
    srli t0, t0, 2
    csrw pmpaddr0, t0
    li t0, -1
    csrw pmpaddr1, t0
    li t0, 0x1f11
    csrw pmpcfg0, t0
    li t0, 0x1808
    csrc mstatus, t0
    la t0, protected_user
    csrw mepc, t0
    mret

protected_user:
    la s0, protected_signature
    la s1, protected_word
    la s2, allowed_word
    li s3, 0x2468ace0
    sw s3, 0(s2)
    li t0, 0xdeadbeef
.globl denied_store
denied_store:
    sw t0, 0(s1)
    lw t0, 0(s1)
    sw t0, 16(s0)
    li t1, DITDAH_CONSOLE_ADDRESS
    li t0, 85
    sw t0, 0(t1)
    li t0, 10
    sw t0, 0(t1)
.globl user_ecall
user_ecall:
    ecall
    j software_done

.balign 4
protected_handler:
    csrr t0, mcause
    li t1, 7
    beq t0, t1, protected_store_fault
    li t1, 8
    bne t0, t1, software_done
    sw t0, 20(s0)
    lw t1, 0(s2)
    sw t1, 24(s0)
    j software_done
protected_store_fault:
    sw t0, 4(s0)
    csrr t1, mepc
    sw t1, 8(s0)
    csrr t0, mtval
    sw t0, 12(s0)
    li t0, 1
    sw t0, 0(s0)
    addi t1, t1, 4
    csrw mepc, t1
    mret
.option pop

.section .data, "aw", @progbits
.balign 4
.globl protected_word
protected_word:
    .word 0x13579bdf
.globl allowed_word
allowed_word:
    .word 0

.section .bss, "aw", @nobits
.balign 4
.globl protected_signature
protected_signature:
    .space 28
