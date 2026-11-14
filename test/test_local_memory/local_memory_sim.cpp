// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VDitDahE2LocalMemoryBench.h"
#include "verilated.h"
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

struct Request { unsigned phase, owner; uint32_t address, write, data, mask, size, machine, operation; };
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    std::ifstream input(argv[1]);
    std::array<std::array<std::vector<Request>, 2>, 3> queues;
    Request item;
    while (input >> item.phase >> item.owner >> item.address >> item.write >> item.data >> item.mask >> item.size >> item.machine >> item.operation)
        queues.at(item.phase).at(item.owner).push_back(item);
    VDitDahE2LocalMemoryBench dut;
    dut.bank = std::stoul(argv[2]);
    const bool delayed = std::stoul(argv[3]);
    unsigned phase = 0, resetUntil = 2, drained = 0;
    std::array<unsigned, 2> position{}, completed{};
    std::cout << "cycle reset phase";
#define HEADER(port) std::cout << " " #port "_request_valid " #port "_request_ready " #port "_request_address " #port "_request_write " #port "_request_data " #port "_request_mask " #port "_request_size " #port "_request_machine " #port "_request_operation " #port "_response_valid " #port "_response_ready " #port "_response_data " #port "_response_fault";
    HEADER(instruction) HEADER(data)
    std::cout << '\n';
    for (unsigned cycle = 0; cycle < 1000000; ++cycle) {
        dut.clock = 0;
        dut.reset = cycle < resetUntil;
#define DRIVE(port, owner) \
        dut.port##_request_valid = !dut.reset && position[owner] < queues[phase][owner].size(); \
        dut.port##_response_ready = !dut.reset && (!delayed || (cycle + owner * 3) % 7 >= 2); \
        if (dut.port##_request_valid) { const auto &r = queues[phase][owner][position[owner]]; \
            dut.port##_request_bits_address = r.address; dut.port##_request_bits_write = r.write; \
            dut.port##_request_bits_data = r.data; dut.port##_request_bits_mask = r.mask; \
            dut.port##_request_bits_size = r.size; dut.port##_request_bits_machine = r.machine; \
            dut.port##_request_bits_operation = r.operation; }
        DRIVE(instruction, 0) DRIVE(data, 1)
        dut.eval();
        std::cout << cycle << ' ' << unsigned(dut.reset) << ' ' << phase;
#define PRINT(port) std::cout << ' ' << unsigned(dut.port##_request_valid) << ' ' << unsigned(dut.port##_request_ready) \
            << ' ' << uint32_t(dut.port##_request_bits_address) << ' ' << unsigned(dut.port##_request_bits_write) \
            << ' ' << uint32_t(dut.port##_request_bits_data) << ' ' << unsigned(dut.port##_request_bits_mask) \
            << ' ' << unsigned(dut.port##_request_bits_size) << ' ' << unsigned(dut.port##_request_bits_machine) \
            << ' ' << unsigned(dut.port##_request_bits_operation) << ' ' << unsigned(dut.port##_response_valid) \
            << ' ' << unsigned(dut.port##_response_ready) << ' ' << uint32_t(dut.port##_response_bits_data) \
            << ' ' << unsigned(dut.port##_response_bits_fault);
        PRINT(instruction) PRINT(data)
        std::cout << '\n';
        if (!dut.reset) {
#define ADVANCE(port, owner) \
            if (dut.port##_request_valid && dut.port##_request_ready) ++position[owner]; \
            if (dut.port##_response_valid && dut.port##_response_ready) ++completed[owner];
            ADVANCE(instruction, 0) ADVANCE(data, 1)
        }
        dut.clock = 1;
        dut.eval();
        const bool done = !dut.reset && position[0] == queues[phase][0].size() && position[1] == queues[phase][1].size()
            && completed[0] == position[0] && completed[1] == position[1];
        drained = done ? drained + 1 : 0;
        if (drained == 4) {
            if (phase == 2) return 0;
            ++phase; position = {}; completed = {}; drained = 0; resetUntil = cycle + 3;
        }
    }
    std::cerr << "Local-memory transaction timeout\n";
    return 3;
}
