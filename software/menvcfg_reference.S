/* SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> */
/* SPDX-License-Identifier: MIT */
.option norvc
.option norelax
.section .text.start,"ax",@progbits
.globl _start, software_done, signature, trap_vector
.globl csr_op0, csr_op1, csr_op2, csr_op3, csr_op4, csr_op5
.globl user_op0, user_op1, user_op2, user_op3, user_op4, user_op5, user_ecall
_start:
    la s0, signature
    la t0, trap_vector
    csrw mtvec, t0
    li s1, 0
    li t2, -1
    li a0, 55
csr_op0:
    csrrw a0, 0x30a, t2
    sw a0, 0(s0)
csr_op1:
    csrrs a0, 0x30a, t2
    sw a0, 4(s0)
csr_op2:
    csrrc a0, 0x30a, t2
    sw a0, 8(s0)
csr_op3:
    csrrwi a0, 0x30a, 31
    sw a0, 12(s0)
csr_op4:
    csrrsi a0, 0x30a, 31
    sw a0, 16(s0)
csr_op5:
    csrrci a0, 0x30a, 31
    sw a0, 20(s0)
#if USER_PROFILE
    csrr a0, 0x30a
    sw a0, 24(s0)
    li t0, -1
    csrw pmpaddr0, t0
    li t0, 31
    csrw pmpcfg0, t0
    la t0, user_start
    csrw mepc, t0
    csrw mstatus, zero
    li a0, 55
    mret
user_start:
user_op0:
    csrrw a0, 0x30a, t2
    sw a0, 32(s0)
user_op1:
    csrrs a0, 0x30a, zero
    sw a0, 36(s0)
user_op2:
    csrrc a0, 0x30a, t2
    sw a0, 40(s0)
user_op3:
    csrrwi a0, 0x30a, 31
    sw a0, 44(s0)
user_op4:
    csrrsi a0, 0x30a, 0
    sw a0, 48(s0)
user_op5:
    csrrci a0, 0x30a, 31
    sw a0, 52(s0)
user_ecall:
    ecall
#else
    j software_done
#endif
trap_vector:
    csrr t3, mcause
    csrr t4, mepc
    csrr t5, mtval
    slli t6, s1, 4
    add t6, s0, t6
    sw t3, 128(t6)
    sw t4, 132(t6)
    sw t5, 136(t6)
    csrr t0, mstatus
    srli t0, t0, 11
    andi t0, t0, 3
    sw t0, 140(t6)
    addi s1, s1, 1
    li t6, 8
    beq t3, t6, software_done
    addi t4, t4, 4
    csrw mepc, t4
    mret
software_done:
    j software_done
.section .data,"aw",@progbits
.balign 4
signature:
    .fill 64,4,0
