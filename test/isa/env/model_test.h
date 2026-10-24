// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#ifndef DITDAH_E2_MODEL_TEST_H
#define DITDAH_E2_MODEL_TEST_H

#define RVMODEL_BOOT
#define RVMODEL_HALT \
  li t0, 1; la t1, tohost; sw t0, 0(t1); \
  .global test_complete; test_complete: j test_complete
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
#define RVMODEL_IO_ASSERT_GPR_EQ(_S, _R, _I) \
  li _S, _I; beq _R, _S, 991f; ebreak; 991:

#endif
