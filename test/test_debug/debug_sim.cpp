// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VDitDahE2.h"
#include "verilated.h"
#include "rvfi_trace.hpp"
#include <cstdlib>
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>

struct Port {
    bool active = false, held = false;
    std::array<uint32_t, 6> request{}, previous{};
    uint64_t due = 0, accepted = 0;
    uint32_t data = 0;
    bool fault = false;
};

struct Action { unsigned kind; uint32_t address, value, mask; };

int main(int argc, char **argv) {
    try {
        if (argc != 7) throw std::runtime_error("Expected image actions seed delay cycle-limit data-fault");
        VerilatedContext context;
        context.commandArgs(argc, argv);
        VDitDahE2 dut{&context};
        std::ofstream rvfi, rvfiInterrupts;
        if (const char *path = std::getenv("DITDAH_E2_RVFI_TRACE")) {
            rvfi.open(path);
            if (!rvfi) throw std::runtime_error("Cannot open retirement trace");
        }
        if (const char *path = std::getenv("DITDAH_E2_RVFI_INTERRUPTS")) {
            rvfiInterrupts.open(path);
            if (!rvfiInterrupts) throw std::runtime_error("Cannot open interrupt trace");
        }
        std::map<uint32_t, uint32_t> memory;
        std::ifstream image(argv[1]), script(argv[2]);
        if (!image || !script) throw std::runtime_error("Cannot open debug inputs");
        uint32_t address, value;
        while (image >> std::hex >> address >> value) memory[address] = value;
        if (!image.eof()) throw std::runtime_error("Malformed debug image");
        std::vector<Action> actions;
        Action action{};
        while (script >> action.kind >> action.address >> action.value >> action.mask) {
            if (action.kind > 10) throw std::runtime_error("Unknown debug action");
            actions.push_back(action);
        }
        if (!script.eof() || actions.empty()) throw std::runtime_error("Malformed debug actions");
        uint32_t state = std::stoul(argv[3]) + 1;
        const unsigned delay = std::stoul(argv[4]);
        const uint64_t limit = std::stoull(argv[5]);
        const uint64_t dataFault = std::stoull(argv[6]);
        auto random = [&]() { state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state; };
        Port instruction, data;
        bool dmiOwned = false, dmiHeld = false;
        std::array<uint32_t, 2> dmiPrevious{};
        uint64_t sequence = 0, currentSequence = 0;
        size_t index = 0;
        uint64_t idleStart = 0, completion = 0;
        bool completing = false, finished = false;
        unsigned busControl = 0, interruptMask = 0;
        unsigned acceptBound = 0, responseBound = 0;
        uint64_t blockedOffer = 0;
        bool offerSeen = false;
        uint64_t interrupts = 0;
        uint32_t lastInterruptCause = 0;
        dut.reset = 1;
        dut.instruction_request_ready = dut.data_request_ready = 0;
        dut.instruction_response_valid = dut.data_response_valid = 0;
        dut.instruction_response_bits_data = dut.data_response_bits_data = 0;
        dut.instruction_response_bits_fault = dut.data_response_bits_fault = 0;
        dut.dmi_request_valid = dut.dmi_response_ready = 0;
        dut.dmi_request_bits_address = dut.dmi_request_bits_data = dut.dmi_request_bits_op = 0;
        dut.interrupts_software = dut.interrupts_timer = dut.interrupts_external = 0;
        dut.timeValue = 0;
        for (int edge = 0; edge < 4; ++edge) { dut.clock = edge & 1; dut.eval(); }
        dut.reset = 0;
        for (uint64_t cycle = 0; cycle < limit; ++cycle) {
            dut.clock = 0;
            const auto current = actions.at(index);
            if (current.kind == 6) {
                busControl = current.value;
                acceptBound = current.address;
                responseBound = current.mask;
                offerSeen = false;
                if ((acceptBound || responseBound) && (acceptBound != 8 || responseBound != 24))
                    throw std::runtime_error("Unsupported bounded native service");
                if (responseBound && delay > responseBound)
                    throw std::runtime_error("Delay exceeds bounded native response service");
            }
            if (current.kind == 9) {
                if (current.value > 7) throw std::runtime_error("Invalid interrupt mask");
                interruptMask = current.value;
            }
            dut.interrupts_software = interruptMask & 1;
            dut.interrupts_timer = (interruptMask >> 1) & 1;
            dut.interrupts_external = (interruptMask >> 2) & 1;
            dut.timeValue = cycle;
            dut.instruction_request_ready = !completing && !instruction.active && (!delay || cycle % 8 == 7 || random() % 3 == 0);
            const bool requestDeadline = acceptBound && offerSeen && cycle - blockedOffer >= acceptBound;
            dut.data_request_ready = !data.active && (requestDeadline || (!(busControl & 1) && (!delay || cycle % 8 == 7 || random() % 3 == 0)));
            dut.instruction_response_valid = instruction.active && cycle >= instruction.due;
            dut.data_response_valid = (!(busControl & 2) || (responseBound && cycle - data.accepted >= responseBound)) && data.active && cycle >= data.due;
            dut.instruction_response_bits_data = instruction.data;
            dut.data_response_bits_data = data.data;
            dut.data_response_bits_fault = data.fault;
            dut.dmi_request_valid = !dmiOwned && current.kind >= 1 && current.kind <= 3;
            dut.dmi_request_bits_address = current.address;
            dut.dmi_request_bits_data = current.kind == 2 ? current.value : 0;
            dut.dmi_request_bits_op = current.kind == 2 ? 2 : 1;
            dut.dmi_response_ready = acceptBound || !delay || cycle % 8 == 7 || random() % 4 == 0;
            dut.eval();
            if (!delay && !completing && instruction.active && dut.instruction_response_valid && dut.instruction_response_ready) {
                dut.instruction_request_ready = 1;
                dut.eval();
            }
            std::cout << "T " << cycle << ' ' << dut.timeValue << ' ' << unsigned(dut.systemReset) << ' ' << interruptMask << '\n';
            if (dut.systemReset && (instruction.active || data.active))
                throw std::runtime_error("System reset preceded accepted memory completion");
            if ((dut.instruction_request_valid && dut.instruction_request_bits_operation) ||
                (dut.data_request_valid && dut.data_request_bits_operation))
                throw std::runtime_error("Atomic request requires the shared memory harness");
            auto native = [&](Port &port, char name, bool valid, bool ready, std::array<uint32_t, 6> request,
                              bool responseValid, bool responseReady) {
                if (port.held && (!valid || request != port.previous))
                    throw std::runtime_error("Native request changed under backpressure");
                if (responseValid && responseReady) {
                    if (!port.active) throw std::runtime_error("Unowned native response");
                    if (port.request[1] && !port.fault) {
                        auto &word = memory[port.request[0] & ~3u];
                        for (unsigned lane = 0; lane < 4; ++lane)
                            if (port.request[3] & (1u << lane))
                                word = (word & ~(255u << (8 * lane))) | (port.request[2] & (255u << (8 * lane)));
                    }
                    std::cout << "S " << cycle << ' ' << name << ' ' << port.data << ' ' << port.fault << '\n';
                    port.active = false;
                }
                if (valid && !port.held) {
                    if (name == 'D' && acceptBound && !offerSeen) { blockedOffer = cycle; offerSeen = true; }
                    std::cout << "P " << cycle << ' ' << name;
                    for (auto part : request) std::cout << ' ' << part;
                    std::cout << '\n';
                }
                port.held = valid && !ready;
                port.previous = request;
                if (valid && ready) {
                    if (port.active) throw std::runtime_error("Native owner overwritten");
                    const auto size = request[4];
                    if (size > 2 || request[0] % (1u << size) || request[5] > 1 ||
                        (name == 'I' && (request[1] || size != 2)) ||
                        request[3] != (request[1] ? ((1u << (1u << size)) - 1) << (request[0] % 4) : 0u))
                        throw std::runtime_error("Invalid native request");
                    port.active = true;
                    port.accepted = cycle;
                    port.request = request;
                    port.data = memory[request[0] & ~3u];
                    port.fault = name == 'D' && request[0] == dataFault;
                    port.due = cycle + 1 + (delay ? random() % delay : 0);
                    std::cout << "Q " << cycle << ' ' << name;
                    for (auto part : request) std::cout << ' ' << part;
                    std::cout << '\n';
                }
            };
#define OBSERVE(port, name) native(port, name, dut.port##_request_valid, dut.port##_request_ready, \
    {dut.port##_request_bits_address, dut.port##_request_bits_write, dut.port##_request_bits_data, \
     dut.port##_request_bits_mask, dut.port##_request_bits_size, dut.port##_request_bits_machine}, \
    dut.port##_response_valid, dut.port##_response_ready)
            OBSERVE(instruction, 'I');
            OBSERVE(data, 'D');
#undef OBSERVE
            bool advance = false;
            if (rvfi.is_open()) writeRvfi(rvfi, dut, cycle);
            if (rvfiInterrupts.is_open()) writeRvfiInterrupt(rvfiInterrupts, dut, cycle);
            if (dut.retire_valid) {
                if (dut.interrupt_valid) throw std::runtime_error("Interrupt and instruction completed together");
                std::cout << "R " << cycle << ' ' << dut.retire_pc << ' ' << dut.retire_word << ' '
                          << dut.retire_nextPc << ' ' << unsigned(dut.retire_rd) << ' ' << unsigned(dut.retire_writes)
                          << ' ' << dut.retire_value << ' ' << unsigned(dut.retire_trap) << ' ' << dut.retire_cause
                          << ' ' << dut.retire_tval << ' ' << unsigned(dut.retire_userMode) << '\n';
                advance = current.kind == 0 && dut.retire_pc == current.address;
            }
            if (dut.interrupt_valid) {
                ++interrupts;
                lastInterruptCause = dut.interrupt_cause;
                std::cout << "N " << cycle << ' ' << dut.interrupt_pc << ' ' << dut.interrupt_target
                          << ' ' << dut.interrupt_cause << '\n';
            }
            if (dut.dmi_request_valid && dut.dmi_request_ready) {
                if (dmiOwned) throw std::runtime_error("DMI owner overwritten");
                dmiOwned = true;
                currentSequence = sequence++;
                std::cout << "J " << cycle << ' ' << currentSequence << ' ' << index << ' '
                          << unsigned(dut.dmi_request_bits_address) << ' ' << unsigned(dut.dmi_request_bits_op)
                          << ' ' << dut.dmi_request_bits_data << '\n';
            }
            const std::array<uint32_t, 2> response{dut.dmi_response_bits_status, dut.dmi_response_bits_data};
            if (dmiHeld && (!dut.dmi_response_valid || response != dmiPrevious))
                throw std::runtime_error("DMI response changed under backpressure");
            dmiHeld = dut.dmi_response_valid && !dut.dmi_response_ready;
            dmiPrevious = response;
            if (dut.dmi_response_valid && dut.dmi_response_ready) {
                if (!dmiOwned) throw std::runtime_error("Unowned DMI response");
                std::cout << "K " << cycle << ' ' << currentSequence << ' ' << response[0] << ' ' << response[1] << '\n';
                dmiOwned = false;
                advance = current.kind != 3 || (response[1] & current.mask) == current.value;
            }
            if (current.kind == 4) advance = cycle - idleStart >= current.value;
            if (current.kind == 6 || current.kind == 9) advance = true;
            if (current.kind == 7) advance = data.active && data.request[0] == current.address;
            if (current.kind == 8) advance = data.held && data.previous[0] == current.address;
            if (current.kind == 10) advance = current.value && interrupts >= current.value && lastInterruptCause == current.address;
            if (current.kind == 5 && !completing) { completing = true; completion = cycle; }
            if (completing && dut.data_request_valid) throw std::runtime_error("Data offer after completion");
            dut.clock = 1;
            dut.eval();
            if (advance) {
                std::cout << "L " << cycle << ' ' << index << '\n';
                ++index;
                if (index >= actions.size()) throw std::runtime_error("Missing finish action");
                idleStart = cycle + 1;
            }
            if (completing && cycle >= completion + 8 && !instruction.active && !data.active && !dmiOwned) {
                std::cout << "F " << cycle + 1 << ' ' << index << '\n';
                finished = true;
                break;
            }
        }
        if (!finished) throw std::runtime_error("Debug execution exceeded cycle limit");
        for (auto [location, word] : memory) std::cout << "W " << location << ' ' << word << '\n';
        dut.final();
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
