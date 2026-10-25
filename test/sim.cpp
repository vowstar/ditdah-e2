// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VDitDahE2.h"
#include "verilated.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

struct Request {
    uint32_t address, data, mask, size;
    bool write, machine;
    bool operator==(const Request &other) const {
        return address == other.address && data == other.data &&
               mask == other.mask && size == other.size && write == other.write && machine == other.machine;
    }
};

struct Port {
    bool active = false, held = false;
    Request request{}, previous{};
    uint64_t due = 0;
    uint32_t data = 0;
    bool fault = false;
};

struct InputEvent {
    char trigger;
    uint64_t key;
    unsigned mask;
    bool fired = false;
    uint64_t delay = 0, due = UINT64_MAX;
};

int main(int argc, char **argv) {
    try {
        if (argc != 8 && argc != 9)
            throw std::runtime_error("Expected image seed delay instruction-fault data-fault limit completion-pc and optional input schedule");
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
        const uint32_t completionPc = std::stoul(argv[7]);
        std::vector<InputEvent> schedule;
        if (argc == 9 && std::string(argv[8]) != "-") {
            std::ifstream events(argv[8]);
            if (!events) throw std::runtime_error("Cannot open input schedule");
            std::string line;
            while (std::getline(events, line)) {
                std::istringstream fields(line);
                InputEvent event{};
                if (!(fields >> event.trigger)) continue;
                if (!(fields >> event.key >> event.mask)) throw std::runtime_error("Malformed input schedule");
                if (event.trigger == 'M' && (!(fields >> event.delay) || !event.delay || event.delay > limit))
                    throw std::runtime_error("Invalid arithmetic interrupt delay");
                std::string extra;
                if (fields >> extra) throw std::runtime_error("Malformed input schedule");
                if (std::string("CDRNM").find(event.trigger) == std::string::npos || event.mask > 7 ||
                    ((event.trigger == 'D' || event.trigger == 'R') && event.key > UINT32_MAX) ||
                    ((event.trigger == 'N' || event.trigger == 'M') && !event.key))
                    throw std::runtime_error("Invalid input schedule");
                schedule.push_back(event);
            }
            if (!events.eof()) throw std::runtime_error("Malformed input schedule");
        }
        unsigned pending = 0;
        uint64_t currentCycle = 0, arithmeticStarts = 0;
        auto apply = [&](char trigger, uint64_t key) {
            for (auto &event : schedule) {
                if (!event.fired && event.trigger == trigger && event.key == key) {
                    if (event.trigger == 'M') event.due = currentCycle + event.delay;
                    else pending = event.mask;
                    event.fired = true;
                }
            }
        };
        Port instruction, data;
        dut.reset = 1;
        dut.instruction_request_ready = dut.data_request_ready = 0;
        dut.instruction_response_valid = dut.data_response_valid = 0;
        dut.instruction_response_bits_data = dut.data_response_bits_data = 0;
        dut.instruction_response_bits_fault = dut.data_response_bits_fault = 0;
        dut.interrupts_software = dut.interrupts_timer = dut.interrupts_external = 0;
        dut.timeValue = 0xfffffff0ULL;
        for (int edge = 0; edge != 4; ++edge) {
            dut.clock = edge & 1; dut.eval();
        }
        dut.reset = 0;
        uint64_t retired = 0, traps = 0, forwards = 0, loadUse = 0, redirects = 0;
        uint64_t memoryWait = 0, blockedRedirect = 0, drainAfterCompletion = 0, quietCycles = 0;
        uint64_t interrupts = 0, sleepCycles = 0;
        bool finished = false, completing = false;
        bool finalOfferValid = false;
        Request finalOffer{};
        for (uint64_t cycle = 0; cycle < limit; ++cycle) {
            dut.clock = 0;
            currentCycle = cycle;
            for (auto &event : schedule) {
                if (event.due == cycle) {
                    pending = event.mask;
                    event.due = UINT64_MAX;
                }
            }
            apply('C', cycle);
            dut.interrupts_software = pending & 1;
            dut.interrupts_timer = (pending >> 1) & 1;
            dut.interrupts_external = (pending >> 2) & 1;
            dut.timeValue = 0xfffffff0ULL + cycle;
            dut.instruction_request_ready = !completing && !instruction.active && (!delay || random() % 3 == 0);
            dut.data_request_ready = !data.active && (!delay || random() % 3 == 0);
            dut.instruction_response_valid = instruction.active && cycle >= instruction.due;
            dut.data_response_valid = data.active && cycle >= data.due;
            dut.instruction_response_bits_data = instruction.data;
            dut.instruction_response_bits_fault = instruction.fault;
            dut.data_response_bits_data = data.data;
            dut.data_response_bits_fault = data.fault;
            dut.eval();
            if (!delay && !completing && instruction.active &&
                dut.instruction_response_valid && dut.instruction_response_ready) {
                dut.instruction_request_ready = 1;
                dut.eval();
            }
            std::cout << "T " << cycle << ' ' << pending << ' ' << dut.timeValue << '\n';
            if (completing && dut.data_request_valid)
                throw std::runtime_error("Data request after program completion");
            forwards += dut.forward; loadUse += dut.loadUse; redirects += dut.redirect;
            memoryWait += dut.memoryWait;
            sleepCycles += dut.sleeping;
            blockedRedirect += dut.redirect && dut.instruction_request_valid && !dut.instruction_request_ready;
            drainAfterCompletion += completing && dut.instruction_response_valid && dut.instruction_response_ready;
            auto observe = [&](Port &port, char name, bool valid, bool ready, Request request,
                               bool responseValid, bool responseReady, uint64_t faultAddress) {
                if (port.held && (!valid || !(request == port.previous)))
                    throw std::runtime_error("Request changed under backpressure");
                if (valid && !port.held)
                    std::cout << "P " << cycle << ' ' << name << ' ' << request.address << ' '
                              << request.write << ' ' << request.data << ' ' << request.mask << ' '
                              << request.size << ' ' << request.machine << '\n';
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
                              << request.write << ' ' << request.data << ' ' << request.mask << ' '
                              << request.size << ' ' << request.machine << '\n';
                    if (name == 'D') apply('D', request.address);
                }
            };
            observe(instruction, 'I', dut.instruction_request_valid, dut.instruction_request_ready,
                    {dut.instruction_request_bits_address, dut.instruction_request_bits_data,
                     dut.instruction_request_bits_mask, dut.instruction_request_bits_size, bool(dut.instruction_request_bits_write), bool(dut.instruction_request_bits_machine)},
                    dut.instruction_response_valid, dut.instruction_response_ready, instructionFault);
            observe(data, 'D', dut.data_request_valid, dut.data_request_ready,
                    {dut.data_request_bits_address, dut.data_request_bits_data,
                     dut.data_request_bits_mask, dut.data_request_bits_size, bool(dut.data_request_bits_write), bool(dut.data_request_bits_machine)},
                    dut.data_response_valid, dut.data_response_ready, dataFault);
            if (dut.retire_valid) {
                if (dut.interrupt_valid) throw std::runtime_error("Interrupt and instruction completed together");
                retired += !dut.retire_trap; traps += dut.retire_trap;
                std::cout << "R " << cycle << ' ' << dut.retire_pc << ' ' << dut.retire_word << ' '
                          << dut.retire_nextPc << ' ' << unsigned(dut.retire_rd) << ' '
                          << unsigned(dut.retire_writes) << ' ' << dut.retire_value << ' '
                          << unsigned(dut.retire_trap) << ' ' << unsigned(dut.retire_cause) << ' '
                          << dut.retire_tval << ' ' << unsigned(dut.retire_userMode) << '\n';
                apply('R', dut.retire_pc);
                if (!dut.retire_trap && dut.retire_pc == completionPc) {
                    if (dut.retire_word != 0x0000006f || dut.retire_nextPc != completionPc)
                        throw std::runtime_error("Invalid program completion instruction");
                    completing = true;
                }
            }
            if (dut.interrupt_valid) {
                ++interrupts;
                std::cout << "N " << cycle << ' ' << dut.interrupt_pc << ' ' << dut.interrupt_target << ' '
                          << dut.interrupt_cause << '\n';
                apply('N', interrupts);
            }
            if (dut.mulDiv_start || dut.mulDiv_resultValid || dut.mulDiv_finish || dut.mulDiv_cancel) {
                std::cout << "U " << cycle << ' ' << dut.mulDiv_pc << ' ' << unsigned(dut.mulDiv_start) << ' '
                          << unsigned(dut.mulDiv_resultValid) << ' ' << unsigned(dut.mulDiv_finish) << ' '
                          << unsigned(dut.mulDiv_cancel) << ' ' << dut.mulDiv_value << '\n';
                if (dut.mulDiv_start) apply('M', ++arithmeticStarts);
            }
            dut.clock = 1; dut.eval();
            if (completing && !instruction.active && !data.active) {
                const bool unchanged = instruction.held == finalOfferValid &&
                                       (!instruction.held || instruction.previous == finalOffer);
                quietCycles = quietCycles && unchanged ? quietCycles + 1 : 1;
                finalOfferValid = instruction.held;
                finalOffer = instruction.previous;
                std::cout << "O " << cycle << ' ' << finalOfferValid << ' ' << finalOffer.address << ' '
                          << finalOffer.write << ' ' << finalOffer.data << ' ' << finalOffer.mask << ' '
                          << finalOffer.size << '\n';
            } else {
                quietCycles = 0;
            }
            if (quietCycles == 8) {
                if (data.held) throw std::runtime_error("Held data request after completion");
                if (instruction.held) {
                    const auto &held = instruction.previous;
                    std::cout << "H " << cycle << ' ' << held.address << ' ' << held.write << ' '
                              << held.data << ' ' << held.mask << ' ' << held.size << '\n';
                }
                std::cout << "C " << cycle + 1 << ' ' << retired << ' ' << traps << ' '
                          << forwards << ' ' << loadUse << ' ' << redirects << ' '
                          << memoryWait << ' ' << blockedRedirect << ' ' << drainAfterCompletion << ' '
                          << interrupts << ' ' << sleepCycles << '\n';
                finished = true;
                break;
            }
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
