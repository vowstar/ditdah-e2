// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#ifndef DITDAH_E2_MODEL_TEST_H
#define DITDAH_E2_MODEL_TEST_H

#define RVMODEL_BOOT
#ifdef __riscv_compressed
#define DITDAH_E2_HALT_ALIGN .option rvc; .balign 4
#else
#define DITDAH_E2_HALT_ALIGN .balign 4
#endif
#define RVMODEL_HALT \
  .option push; DITDAH_E2_HALT_ALIGN; .option norvc; \
  li t0, 1; la t1, tohost; sw t0, 0(t1); \
  .global test_complete; test_complete: jal zero, test_complete; .option pop
#define RVMODEL_DATA_BEGIN \
  .section .signature,"aw",@progbits; .balign 4; \
  .global begin_signature; begin_signature:
#define RVMODEL_DATA_END \
  .global end_signature; end_signature: \
  .section .tohost,"aw",@progbits; .balign 8; \
  .global tohost; tohost: .dword 0; \
  .global fromhost; fromhost: .dword 0
#define RVMODEL_IO_INIT
#define RVMODEL_IO_WRITE_STR(_R, _STR)
#ifdef DITDAH_E2_BIT_SIGNATURE
#define RVMODEL_IO_ASSERT_GPR_EQ(_S, _R, _I)
#else
#define RVMODEL_IO_ASSERT_GPR_EQ(_S, _R, _I) \
  li _S, _I; beq _R, _S, 991f; ebreak; 991:
#endif

#endif
