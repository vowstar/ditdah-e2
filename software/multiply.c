// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

#ifndef __riscv_mul
unsigned int __mulsi3(unsigned int left, unsigned int right)
{
    unsigned int product = 0;
    while (right) {
        if (right & 1)
            product += left;
        left <<= 1;
        right >>= 1;
    }
    return product;
}
#endif
