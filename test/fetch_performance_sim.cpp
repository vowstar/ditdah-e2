// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VFetchPerformanceBench.h"
#include "verilated.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

int main(int argc, char **argv) {
    try {
        if (argc != 5) throw std::runtime_error("Expected image transport delay completion-pc");
        VerilatedContext context;
        context.commandArgs(argc, argv);
        VFetchPerformanceBench dut{&context};
        std::ifstream input(argv[1]);
        std::map<uint32_t, uint32_t> memory;
        uint32_t address, value;
        while (input >> std::hex >> address >> value) memory[address] = value;
        if (!input.eof()) throw std::runtime_error("Malformed image");
        const bool axi = std::string(argv[2]) == "axi";
        if (!axi && std::string(argv[2]) != "native") throw std::runtime_error("Unknown transport");
        const unsigned delay = std::stoul(argv[3]);
        const uint32_t done = std::stoul(argv[4]);
        bool nativeActive = false, axiActive = false, completed = false, finished = false;
        uint64_t nativeDue = 0, axiDue = 0, completionCycle = 0;
        uint32_t nativeData = 0, axiData = 0;
        dut.clock = 0;
        dut.reset = 1;
        dut.n_i_ready = dut.n_i_valid = dut.n_i_data = dut.n_i_fault = 0;
        dut.a_ar_ready = dut.a_r_valid = dut.a_r_data = dut.a_r_response = 0;
        for (unsigned edge = 0; edge != 4; ++edge) { dut.clock = edge & 1; dut.eval(); }
        dut.reset = 0;
        for (uint64_t cycle = 0; cycle != 100000; ++cycle) {
            dut.clock = 0;
            const bool accepting = !delay || cycle % 3 != 0;
            dut.n_i_valid = !axi && nativeActive && cycle >= nativeDue;
            dut.n_i_data = nativeData;
            dut.a_r_valid = axi && axiActive && cycle >= axiDue;
            dut.a_r_data = axiData;
            dut.a_ar_ready = axi && !axiActive && accepting;
            dut.n_i_ready = 0;
            dut.eval();
            dut.n_i_ready = !axi && !completed && accepting &&
                (!nativeActive || (dut.i_rv && dut.i_rr));
            dut.eval();
            if (dut.d_valid || dut.a_aw_valid || dut.a_w_valid || dut.interrupt_valid)
                throw std::runtime_error("Unexpected data, write or interrupt activity");
            std::cout << "T " << cycle << ' ' << unsigned(dut.f_valid) << ' '
                      << unsigned(dut.f_ready) << ' ' << unsigned(dut.f_pause) << ' '
                      << unsigned(dut.f_redirect) << ' ' << dut.f_pc << '\n';
            std::cout << "I " << cycle << ' ' << unsigned(dut.i_valid) << ' '
                      << unsigned(dut.i_ready) << ' ' << dut.i_address << ' '
                      << unsigned(dut.i_write) << ' ' << dut.i_data << ' '
                      << unsigned(dut.i_mask) << ' ' << unsigned(dut.i_size) << ' '
                      << unsigned(dut.i_machine) << ' ' << unsigned(dut.i_operation) << ' '
                      << unsigned(dut.i_rv) << ' ' << unsigned(dut.i_rr) << ' '
                      << dut.i_rd << ' ' << unsigned(dut.i_fault) << '\n';
            std::cout << "A " << cycle << ' ' << unsigned(dut.a_ar_valid) << ' '
                      << unsigned(dut.a_ar_ready) << ' ' << dut.a_ar_address << ' '
                      << unsigned(dut.a_ar_protection) << ' ' << unsigned(dut.a_r_valid) << ' '
                      << unsigned(dut.a_r_ready) << ' ' << dut.a_r_data << ' '
                      << unsigned(dut.a_r_response) << '\n';
            if (dut.i_rv && dut.i_rr) {
                if (!nativeActive) throw std::runtime_error("Native response has no owner");
                nativeActive = false;
            }
            if (dut.i_valid && dut.i_ready) {
                if (nativeActive) throw std::runtime_error("Native ownership overlap");
                nativeActive = true;
                nativeData = memory[dut.i_address];
                nativeDue = cycle + 1 + delay;
            }
            if (dut.a_r_valid && dut.a_r_ready) {
                if (!axiActive) throw std::runtime_error("AXI response has no owner");
                axiActive = false;
            }
            if (dut.a_ar_valid && dut.a_ar_ready) {
                if (axiActive) throw std::runtime_error("AXI ownership overlap");
                axiActive = true;
                axiData = memory[dut.a_ar_address];
                axiDue = cycle + 1 + delay;
            }
            if (dut.retire_valid) {
                std::cout << "R " << cycle << ' ' << dut.retire_pc << ' ' << dut.retire_word << ' '
                          << dut.retire_nextPc << ' ' << unsigned(dut.retire_rd) << ' '
                          << unsigned(dut.retire_writes) << ' ' << dut.retire_value << ' '
                          << unsigned(dut.retire_trap) << ' ' << dut.retire_cause << ' '
                          << dut.retire_tval << ' ' << unsigned(dut.retire_userMode) << '\n';
                if (dut.retire_pc == done && !completed) {
                    completed = true;
                    completionCycle = cycle;
                }
            }
            dut.clock = 1;
            dut.eval();
            if (completed && cycle >= completionCycle + 8 && !nativeActive && !axiActive) {
                std::cout << "F " << cycle + 1 << '\n';
                finished = true;
                break;
            }
        }
        if (!finished) throw std::runtime_error("Performance execution timeout");
        dut.final();
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
