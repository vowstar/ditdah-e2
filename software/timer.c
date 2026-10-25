// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "platform.h"

typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
_Static_assert(sizeof(uint32_t) == 4, "Expected a 32-bit integer");

volatile uint32_t timer_events;
volatile uint32_t timer_errors;
volatile uint32_t timer_observations[3];

static volatile uint32_t *const timer = (volatile uint32_t *)DITDAH_TIMER_BASE;
static volatile uint32_t *const console = (volatile uint32_t *)DITDAH_CONSOLE_BASE;

static uint64_t read_time(void)
{
    uint32_t upper, lower, again;
    do {
        upper = timer[1];
        lower = timer[0];
        again = timer[1];
    } while (upper != again);
    return ((uint64_t)upper << 32) | lower;
}

static void set_compare(uint64_t value)
{
    timer[2] = 0xffffffffu;
    timer[3] = value >> 32;
    timer[2] = (uint32_t)value;
}

__attribute__((interrupt("machine"), aligned(4)))
static void timer_handler(void)
{
    uint32_t cause;
    __asm__ volatile ("csrr %0, mcause" : "=r"(cause));
    if (cause != 0x80000007u || timer_events >= 3) {
        timer_errors = 1;
        __asm__ volatile ("csrw mie, zero" ::: "memory");
        set_compare(~(uint64_t)0);
        return;
    }
    uint64_t now = read_time();
    timer_observations[timer_events] = (uint32_t)now;
    timer_events++;
    if (timer_events == 3) {
        __asm__ volatile ("csrw mie, zero" ::: "memory");
        set_compare(~(uint64_t)0);
    } else {
        set_compare(now + 20);
    }
}

int main(void)
{
    __asm__ volatile ("csrw mtvec, %0" :: "r"(timer_handler) : "memory");
    set_compare(read_time() + 20);
    __asm__ volatile ("csrw mie, %0" :: "r"(128u) : "memory");
    __asm__ volatile ("csrsi mstatus, 8" ::: "memory");
    for (;;) {
        __asm__ volatile ("csrci mstatus, 8" ::: "memory");
        if (timer_events == 3 || timer_errors) {
            break;
        }
        __asm__ volatile ("wfi" ::: "memory");
        __asm__ volatile ("csrsi mstatus, 8" ::: "memory");
    }
    *console = 'E';
    *console = '2';
    *console = '0' + timer_events;
    *console = '\n';
    return 0;
}
