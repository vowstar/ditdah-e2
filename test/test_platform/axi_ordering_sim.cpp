// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VPlatformBench.h"
#include "verilated.h"
#include <array>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

struct NativeOwner {
    bool active = false, held = false;
    std::array<uint32_t, 6> request{};
};

struct PendingRead {
    uint64_t due;
    uint32_t data;
    bool fault;
};

int main(int argc, char **argv) {
    try {
        if (argc != 3) throw std::runtime_error("Expected image schedule");
        VerilatedContext context;
        context.commandArgs(argc, argv);
        VPlatformBench dut{&context};
        std::ifstream image(argv[1]);
        uint32_t done, dataFault, instructionFault, slowInstruction;
        if (!(image >> std::hex >> done >> dataFault >> instructionFault >> slowInstruction))
            throw std::runtime_error("Missing ordering image header");
        const unsigned schedule = std::stoul(argv[2]);
        if (schedule > 2) throw std::runtime_error("Unknown ordering schedule");
        std::map<uint32_t, uint32_t> memory;
        uint32_t address, word;
        while (image >> std::hex >> address >> word) memory[address] = word;
        if (!image.eof()) throw std::runtime_error("Malformed ordering image");
        std::deque<PendingRead> reads;
        bool aw = false, w = false, b = false, finished = false;
        uint32_t writeAddress = 0, writeData = 0, mask = 0;
        uint64_t writeDue = 0, completion = 0;
        std::array<NativeOwner, 2> native{};
        std::array<NativeOwner, 3> held{};
        dut.clock = 0;
        dut.reset = 1;
        dut.tick = dut.externalInterrupt = 0;
        dut.transmit_ready = 1;
        dut.axi_ar_ready = dut.axi_aw_ready = dut.axi_w_ready = 0;
        dut.axi_r_valid = dut.axi_b_valid = 0;
        dut.axi_r_bits_data = dut.axi_r_bits_response = dut.axi_b_bits_response = 0;
        for (unsigned edge = 0; edge < 4; ++edge) { dut.clock = edge & 1; dut.eval(); }
        dut.reset = 0;
        for (uint64_t cycle = 0; cycle < 10000; ++cycle) {
            dut.clock = 0;
            dut.axi_ar_ready = reads.size() < 2;
            dut.axi_aw_ready = !aw && !b && (schedule != 1 || cycle % 5 == 0);
            dut.axi_w_ready = !w && !b && (schedule != 0 || cycle % 7 == 0);
            dut.axi_r_valid = !reads.empty() && cycle >= reads.front().due;
            dut.axi_r_bits_data = reads.empty() ? 0 : reads.front().data;
            dut.axi_r_bits_response = !reads.empty() && reads.front().fault ? 3 : 0;
            dut.axi_b_valid = b && cycle >= writeDue;
            dut.axi_b_bits_response = writeAddress == dataFault ? 2 : 0;
            dut.eval();
            std::cout << "T " << cycle << '\n';
            auto observe = [&](unsigned index, char name, bool valid, bool ready,
                               std::array<uint32_t, 6> request, bool rv, bool rr,
                               uint32_t value, bool fault) {
                auto &owner = native[index];
                if (owner.held && (!valid || request != owner.request))
                    throw std::runtime_error("Native request changed while stalled");
                owner.held = valid && !ready;
                owner.request = request;
                if (rv && rr) {
                    if (!owner.active) throw std::runtime_error("Native response lacks owner");
                    owner.active = false;
                    std::cout << "S " << cycle << ' ' << name << ' ' << value << ' ' << fault << '\n';
                }
                if (valid && ready) {
                    if (owner.active) throw std::runtime_error("Native request replaced owner");
                    owner.active = true;
                    std::cout << "Q " << cycle << ' ' << name;
                    for (auto item : request) std::cout << ' ' << item;
                    std::cout << '\n';
                }
            };
#define OBSERVE(index, name, p) observe(index, name, dut.o_##p##_request_valid, dut.o_##p##_request_ready, \
    {dut.o_##p##_request_bits_address, dut.o_##p##_request_bits_write, dut.o_##p##_request_bits_data, \
     dut.o_##p##_request_bits_mask, dut.o_##p##_request_bits_size, dut.o_##p##_request_bits_machine}, \
     dut.o_##p##_response_valid, dut.o_##p##_response_ready, dut.o_##p##_response_bits_data, dut.o_##p##_response_bits_fault)
            OBSERVE(0, 'I', i);
            OBSERVE(1, 'D', d);
#undef OBSERVE
            auto stable = [&](unsigned index, bool valid, bool ready, std::array<uint32_t, 6> payload) {
                auto &previous = held[index];
                if (previous.held && (!valid || payload != previous.request))
                    throw std::runtime_error("AXI request changed while stalled");
                previous.held = valid && !ready;
                previous.request = payload;
            };
            stable(0, dut.axi_ar_valid, dut.axi_ar_ready, {dut.axi_ar_bits_address, dut.axi_ar_bits_protection});
            stable(1, dut.axi_aw_valid, dut.axi_aw_ready, {dut.axi_aw_bits_address, dut.axi_aw_bits_protection});
            stable(2, dut.axi_w_valid, dut.axi_w_ready, {dut.axi_w_bits_data, dut.axi_w_bits_strobe});
            if (dut.axi_r_valid && dut.axi_r_ready) {
                const auto read = reads.front();
                std::cout << "A " << cycle << " R " << read.data << ' ' << (read.fault ? 3 : 0) << '\n';
                reads.pop_front();
            }
            if (dut.axi_b_valid && dut.axi_b_ready) {
                const bool fault = writeAddress == dataFault;
                std::cout << "A " << cycle << " B " << (fault ? 2 : 0) << '\n';
                if (!fault) {
                    auto &value = memory[writeAddress];
                    for (unsigned lane = 0; lane < 4; ++lane)
                        if (mask & (1u << lane))
                            value = (value & ~(255u << (8 * lane))) | (writeData & (255u << (8 * lane)));
                }
                aw = w = b = false;
            }
            if (dut.axi_ar_valid && dut.axi_ar_ready) {
                const uint32_t at = dut.axi_ar_bits_address;
                const bool instruction = dut.axi_ar_bits_protection & 4;
                const bool fault = at == (instruction ? instructionFault : dataFault);
                const uint64_t delay = !instruction ? 80 : at == slowInstruction && schedule == 2 ? 120 : 3;
                reads.push_back({cycle + delay, memory[at], fault});
                std::cout << "A " << cycle << " AR " << at << ' ' << unsigned(dut.axi_ar_bits_protection) << '\n';
            }
            if (dut.axi_aw_valid && dut.axi_aw_ready) {
                aw = true;
                writeAddress = dut.axi_aw_bits_address;
                std::cout << "A " << cycle << " AW " << writeAddress << ' ' << unsigned(dut.axi_aw_bits_protection) << '\n';
            }
            if (dut.axi_w_valid && dut.axi_w_ready) {
                w = true;
                writeData = dut.axi_w_bits_data;
                mask = dut.axi_w_bits_strobe;
                std::cout << "A " << cycle << " W " << writeData << ' ' << mask << '\n';
            }
            if (aw && w && !b) { b = true; writeDue = cycle + 80; }
            if (dut.interrupt_valid || dut.transmit_valid || dut.o_console_request_valid || dut.o_timer_request_valid)
                throw std::runtime_error("Unexpected device activity in ordering workload");
            if (dut.retire_valid) {
                std::cout << "R " << cycle << ' ' << dut.retire_pc << ' ' << dut.retire_word << ' '
                          << dut.retire_nextPc << ' ' << unsigned(dut.retire_rd) << ' '
                          << unsigned(dut.retire_writes) << ' ' << dut.retire_value << ' '
                          << unsigned(dut.retire_trap) << ' ' << dut.retire_cause << ' ' << dut.retire_tval << '\n';
                if (dut.retire_pc == done && !completion) completion = cycle;
            }
            dut.clock = 1;
            dut.eval();
            if (completion && cycle > completion + 8 && reads.empty() && !aw && !w && !b &&
                !native[0].active && !native[1].active) {
                std::cout << "F " << cycle + 1 << '\n';
                finished = true;
                break;
            }
        }
        if (!finished) throw std::runtime_error("Ordering workload timed out");
        for (const auto &[at, value] : memory) std::cout << "W " << at << ' ' << value << '\n';
        dut.final();
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
