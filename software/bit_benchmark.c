// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include <stdint.h>

volatile const uint32_t benchmark_input[32] = {
    0x9e3779b9u, 0x3d6cf076u, 0xd8a26b23u, 0x7bdbefe8u,
    0x131d6c8du, 0xb046d542u, 0x55884617u, 0xf6b5d8d4u,
    0x87e35fa1u, 0x2738da1eu, 0xc67624dbu, 0x618f9580u,
    0x04c90a55u, 0xaa128f2au, 0x4b5c0befu, 0xec69b6acu,
    0x918f2509u, 0x0ec4bc46u, 0xac3a3ef3u, 0x4f73bb38u,
    0xeea4c07du, 0x8dee4ab2u, 0x20d7adc7u, 0xc21d2c04u,
    0x6b5aab71u, 0x089017aeu, 0xb5ed98ebu, 0x55270150u,
    0xf0709d85u, 0x97ba14dau, 0x368be71fu, 0xd9d16a5cu,
};
volatile const uint32_t benchmark_indices[64] = {
    0x00000013u, 0x0000005cu, 0x000000a4u, 0x000000efu,
    0x00000035u, 0x00000082u, 0x000000cau, 0x00000011u,
    0x0000005fu, 0x000000a0u, 0x000000e8u, 0x00000033u,
    0x00000079u, 0x000000ceu, 0x00000016u, 0x0000005du,
    0x000000abu, 0x000000e4u, 0x0000003cu, 0x00000077u,
    0x000000cdu, 0x0000001au, 0x00000052u, 0x000000a9u,
    0x000000e7u, 0x00000038u, 0x00000070u, 0x000000cbu,
    0x00000001u, 0x00000056u, 0x000000aeu, 0x000000e5u,
    0x00000023u, 0x0000006cu, 0x000000d4u, 0x0000001fu,
    0x00000045u, 0x000000b2u, 0x000000fau, 0x00000021u,
    0x0000006fu, 0x000000d0u, 0x00000018u, 0x00000043u,
    0x00000089u, 0x000000feu, 0x00000026u, 0x0000006du,
    0x000000dbu, 0x00000014u, 0x0000004cu, 0x00000087u,
    0x000000fdu, 0x0000002au, 0x00000062u, 0x000000d9u,
    0x00000017u, 0x00000048u, 0x00000080u, 0x000000fbu,
    0x00000031u, 0x00000066u, 0x000000deu, 0x00000015u,
};
volatile uint32_t benchmark_output[32];
volatile uint32_t benchmark_return;

__attribute__((noinline, noclone, section(".text.benchmark")))
uint32_t benchmark(void) {
#if WORKLOAD == 0
    uint32_t sum = 0;
    for (uint32_t i = 0; i < 64; ++i)
        sum += benchmark_input[benchmark_indices[i] & 31];
    benchmark_output[0] = sum;
    return sum;
#elif WORKLOAD == 1
    for (uint32_t i = 0; i < 64; ++i) {
        uint32_t index = benchmark_indices[i];
        benchmark_output[index >> 5] |= UINT32_C(1) << (index & 31);
    }
    return 0;
#elif WORKLOAD == 2
    for (uint32_t i = 0; i < 32; ++i) {
        uint32_t value = benchmark_input[i];
        benchmark_output[i] = (value << 24) | ((value & 0xff00u) << 8)
            | ((value >> 8) & 0xff00u) | (value >> 24);
    }
    return 0;
#else
#error Unknown workload
#endif
}
