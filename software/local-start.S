# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

.file "local-start.S"
.section .text.start, "ax", @progbits
.option norvc
.option norelax
.globl _start
.type _start, @function
_start:
    la t0, __itcm_image_start
    la t1, __itcm_image_end
    la t2, __itcm_destination
    jal ra, .Lcopy
    la t0, __dtcm_image_start
    la t1, __dtcm_image_end
    la t2, __dtcm_destination
    jal ra, .Lcopy
    fence.i
    la t0, __payload_entry
    jalr zero, 0(t0)

.Lcopy:
    beq t0, t1, .Lreturn
    lw t3, 0(t0)
    sw t3, 0(t2)
    addi t0, t0, 4
    addi t2, t2, 4
    jal zero, .Lcopy
.Lreturn:
    jalr zero, 0(ra)
.size _start, .-_start
