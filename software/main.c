// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

typedef unsigned int uint32_t;
_Static_assert(sizeof(uint32_t) == 4, "Expected a 32-bit integer");

volatile uint32_t software_seed = 0x13579bdf;
volatile uint32_t software_factor = 37;
volatile uint32_t software_signature;
volatile uint32_t software_product;

int main(void)
{
    static const uint32_t input[] = {3, 1, 4, 1, 5, 9, 2, 6};
    volatile uint32_t *const console = (volatile uint32_t *)0x10000000;
    uint32_t value = software_seed;
    for (uint32_t index = 0; index < 64; index++) {
        value = ((value << 5) | (value >> 27)) ^ input[index & 7] ^ index;
    }
    software_signature = value;
    software_product = software_seed * software_factor;
    *console = 'E';
    *console = '2';
    *console = '\n';
    return 0;
}
