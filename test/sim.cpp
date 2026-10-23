// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VDitDahE2.h"
#include "verilated.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

struct Request {
    uint32_t address, data, mask, size;
    bool write;
    bool operator==(const Request &other) const {
        return address == other.address && data == other.data &&
               mask == other.mask && size == other.size && write == other.write;
    }
};

struct Port {
    bool active = false, held = false;
    Request request{}, previous{};
    uint64_t due = 0;
    uint32_t data = 0;
    bool fault = false;
};

int main(int argc, char **argv) {
    try {
        if (argc != 7) throw std::runtime_error("Expected image seed delay instruction-fault data-fault limit");
        VerilatedContext context;
        context.commandArgs(argc, argv);
        VDitDahE2 dut{&context};
        std::map<uint32_t, uint32_t> memory;
        std::ifstream file(argv[1]);
        if (!file) throw std::runtime_error("Cannot open program image");
        uint32_t address, word;
        while (file >> std::hex >> address >> word) memory[address] = word;
        uint32_t state = std::stoul(argv[2]) + 1;
        auto random = [&]() { state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state; };
        const auto delay = std::stoul(argv[3]);
        const uint64_t instructionFault = std::stoull(argv[4]);
        const uint64_t dataFault = std::stoull(argv[5]);
        const auto limit = std::stoul(argv[6]);
        Port instruction, data;
        dut.reset = 1;
        dut.instruction_request_ready = dut.data_request_ready = 0;
        dut.instruction_response_valid = dut.data_response_valid = 0;
        dut.instruction_response_bits_data = dut.data_response_bits_data = 0;
        dut.instruction_response_bits_fault = dut.data_response_bits_fault = 0;
        for (int edge = 0; edge != 4; ++edge) {
            dut.clock = edge & 1; dut.eval();
        }
        dut.reset = 0;
        uint64_t retired = 0, traps = 0, forwards = 0, loadUse = 0, redirects = 0;
        uint64_t memoryWait = 0, blockedRedirect = 0, drainAfterHalt = 0;
        bool finished = false;
        for (uint64_t cycle = 0; cycle < limit; ++cycle) {
            dut.clock = 0;
            dut.instruction_request_ready = !instruction.active && (!delay || random() % 3 == 0);
            dut.data_request_ready = !data.active && (!delay || random() % 3 == 0);
            dut.instruction_response_valid = instruction.active && cycle >= instruction.due;
            dut.data_response_valid = data.active && cycle >= data.due;
            dut.instruction_response_bits_data = instruction.data;
            dut.instruction_response_bits_fault = instruction.fault;
            dut.data_response_bits_data = data.data;
            dut.data_response_bits_fault = data.fault;
            dut.eval();
            if (dut.idle) {
                if (instruction.active || data.active || instruction.held || data.held)
                    throw std::runtime_error("Idle with an uncompleted transaction");
                std::cout << "C " << cycle << ' ' << retired << ' ' << traps << ' '
                          << forwards << ' ' << loadUse << ' ' << redirects << ' '
                          << memoryWait << ' ' << blockedRedirect << ' ' << drainAfterHalt << '\n';
                finished = true; break;
            }
            forwards += dut.forward; loadUse += dut.loadUse; redirects += dut.redirect;
            memoryWait += dut.memoryWait;
            blockedRedirect += dut.redirect && dut.instruction_request_valid && !dut.instruction_request_ready;
            drainAfterHalt += dut.halted && dut.instruction_response_valid && dut.instruction_response_ready;
            auto observe = [&](Port &port, char name, bool valid, bool ready, Request request,
                               bool responseValid, bool responseReady, uint64_t faultAddress) {
                if (port.held && (!valid || !(request == port.previous)))
                    throw std::runtime_error("Request changed under backpressure");
                port.held = valid && !ready;
                port.previous = request;
                if (responseValid && responseReady) {
                    if (!port.active) throw std::runtime_error("Unowned response");
                    if (port.request.write && !port.fault) {
                        auto &value = memory[port.request.address & ~3u];
                        for (unsigned lane = 0; lane < 4; ++lane)
                            if (port.request.mask & (1u << lane))
                                value = (value & ~(255u << (8 * lane))) | (port.request.data & (255u << (8 * lane)));
                    }
                    std::cout << "S " << cycle << ' ' << name << ' ' << port.data << ' ' << port.fault << '\n';
                    port.active = false;
                }
                if (valid && ready) {
                    if (port.active) throw std::runtime_error("Multiple outstanding requests");
                    if (request.size > 2 || request.address % (1u << request.size) ||
                        (name == 'I' && (request.write || request.size != 2)) ||
                        request.mask != (request.write ? ((1u << (1u << request.size)) - 1) << (request.address % 4) : 0u))
                        throw std::runtime_error("Invalid native memory request");
                    port.active = true; port.request = request;
                    port.data = memory[request.address & ~3u];
                    port.fault = request.address == faultAddress;
                    port.due = cycle + 1 + (delay ? random() % (name == 'I' ? 3 : delay) : 0);
                    std::cout << "Q " << cycle << ' ' << name << ' ' << request.address << ' '
                              << request.write << ' ' << request.data << ' ' << request.mask << ' ' << request.size << '\n';
                }
            };
            observe(instruction, 'I', dut.instruction_request_valid, dut.instruction_request_ready,
                    {dut.instruction_request_bits_address, dut.instruction_request_bits_data,
                     dut.instruction_request_bits_mask, dut.instruction_request_bits_size, bool(dut.instruction_request_bits_write)},
                    dut.instruction_response_valid, dut.instruction_response_ready, instructionFault);
            observe(data, 'D', dut.data_request_valid, dut.data_request_ready,
                    {dut.data_request_bits_address, dut.data_request_bits_data,
                     dut.data_request_bits_mask, dut.data_request_bits_size, bool(dut.data_request_bits_write)},
                    dut.data_response_valid, dut.data_response_ready, dataFault);
            if (dut.retire_valid) {
                retired += !dut.retire_trap; traps += dut.retire_trap;
                std::cout << "R " << cycle << ' ' << dut.retire_pc << ' ' << dut.retire_word << ' '
                          << dut.retire_nextPc << ' ' << unsigned(dut.retire_rd) << ' '
                          << unsigned(dut.retire_writes) << ' ' << dut.retire_value << ' '
                          << unsigned(dut.retire_trap) << ' ' << unsigned(dut.retire_cause) << ' '
                          << dut.retire_tval << '\n';
            }
            dut.clock = 1; dut.eval();
        }
        if (!finished) throw std::runtime_error("Execution timeout");
        for (const auto &[location, value] : memory) std::cout << "W " << location << ' ' << value << '\n';
        dut.final();
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
