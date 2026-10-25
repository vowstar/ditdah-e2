// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VAtomicBench.h"
#include "verilated.h"
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>

struct Port {
    bool held = false, active = false;
    std::array<uint32_t, 7> request{};
};
struct Competition { uint32_t trigger, address, size, write, data, hold; };
struct DebugAction { unsigned kind; uint32_t address, value, mask; };

int main(int argc, char **argv) {
    try {
        if (argc != 6) throw std::runtime_error("Expected image events seed delay completion-pc");
        VerilatedContext context;
        context.commandArgs(argc, argv);
        VAtomicBench dut{&context};
        std::ifstream image(argv[1]), events(argv[2]);
        std::map<uint32_t, uint32_t> rom;
        uint32_t address, value;
        while (image >> std::hex >> address >> value) rom[address] = value;
        if (!image.eof()) throw std::runtime_error("Malformed atomic image");
        unsigned count;
        if (!(events >> count)) throw std::runtime_error("Missing atomic events");
        std::vector<Competition> competitors(count);
        for (auto &item : competitors)
            if (!(events >> item.trigger >> item.address >> item.size >> item.write >> item.data >> item.hold))
                throw std::runtime_error("Malformed competitor event");
        if (!(events >> count)) throw std::runtime_error("Missing signature addresses");
        std::vector<uint32_t> signatures(count);
        for (auto &item : signatures)
            if (!(events >> item)) throw std::runtime_error("Malformed signature address");
        if (!(events >> count)) throw std::runtime_error("Missing interrupt schedule");
        std::vector<uint32_t> interrupts(count);
        for (auto &item : interrupts)
            if (!(events >> item)) throw std::runtime_error("Malformed interrupt trigger");
        if (!(events >> count)) throw std::runtime_error("Missing DMI schedule");
        std::vector<DebugAction> debugActions(count);
        for (auto &item : debugActions)
            if (!(events >> item.kind >> item.address >> item.value >> item.mask) || item.kind > 4)
                throw std::runtime_error("Malformed DMI action");
        uint32_t state = std::stoul(argv[3]) + 1;
        const unsigned delay = std::stoul(argv[4]);
        const uint32_t done = std::stoul(argv[5]);
        auto random = [&]() { state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state; };
        bool readActive = false, readFault = false;
        uint32_t readData = 0;
        uint64_t readDue = 0;
        std::array<Port, 4> ports{};
        Port axi;
        bool compOffered = false, compActive = false, compSignature = false;
        Competition comp{};
        uint64_t compReadyCycle = 0;
        size_t competitorIndex = 0, signatureIndex = 0;
        size_t interruptIndex = 0;
        bool externalInterrupt = false;
        size_t debugIndex = 0;
        bool dmiActive = false, dmiHeld = false;
        uint64_t sequence = 0, currentSequence = 0, debugStart = 0;
        std::array<uint32_t, 2> previousDmi{};
        bool completed = false, finished = false;
        uint64_t completionCycle = 0;
        dut.reset = 1;
        dut.dmi_request_valid = dut.dmi_response_ready = 0;
        dut.dmi_request_bits_address = dut.dmi_request_bits_data = dut.dmi_request_bits_op = 0;
        dut.tick = dut.externalInterrupt = 0;
        dut.transmit_ready = 1;
        dut.axi_aw_ready = dut.axi_w_ready = dut.axi_ar_ready = 0;
        dut.axi_b_valid = dut.axi_r_valid = 0;
        dut.axi_b_bits_response = dut.axi_r_bits_response = dut.axi_r_bits_data = 0;
        dut.competitor_request_valid = dut.competitor_response_ready = 0;
        dut.competitor_request_bits_address = dut.competitor_request_bits_data = 0;
        dut.competitor_request_bits_machine = dut.competitor_request_bits_write = 0;
        dut.competitor_request_bits_mask = dut.competitor_request_bits_size = dut.competitor_request_bits_operation = 0;
        for (int edge = 0; edge < 4; ++edge) { dut.clock = edge & 1; dut.eval(); }
        dut.reset = 0;
        for (uint64_t cycle = 0; cycle < 100000; ++cycle) {
            dut.clock = 0;
            dut.externalInterrupt = externalInterrupt;
            const auto action = debugIndex < debugActions.size() ? debugActions[debugIndex] : DebugAction{5, 0, 0, 0};
            dut.dmi_request_valid = !dmiActive && action.kind >= 1 && action.kind <= 3;
            dut.dmi_request_bits_address = action.address;
            dut.dmi_request_bits_data = action.kind == 2 ? action.value : 0;
            dut.dmi_request_bits_op = action.kind == 2 ? 2 : 1;
            dut.dmi_response_ready = !delay || cycle % 8 == 7 || random() % 4 == 0;
            if (completed && !compOffered && !compActive && signatureIndex < signatures.size()) {
                comp = {0, signatures[signatureIndex], 2, 0, 0, 0};
                compOffered = compSignature = true;
            }
            dut.axi_ar_ready = !readActive && (!delay || cycle % 8 == 7 || random() % 3 == 0);
            dut.axi_r_valid = readActive && cycle >= readDue;
            dut.axi_r_bits_data = readData;
            dut.axi_r_bits_response = readFault ? 3 : 0;
            dut.competitor_request_valid = compOffered;
            dut.competitor_request_bits_address = comp.address;
            dut.competitor_request_bits_machine = 1;
            dut.competitor_request_bits_write = comp.write;
            dut.competitor_request_bits_data = comp.data;
            dut.competitor_request_bits_size = comp.size;
            dut.competitor_request_bits_mask = comp.write ? ((1u << (1u << comp.size)) - 1) << (comp.address % 4) : 0;
            dut.competitor_response_ready = compActive && cycle >= compReadyCycle;
            dut.eval();
            std::cout << "T " << cycle << ' ' << dut.timeValue << ' ' << unsigned(dut.o_reset)
                      << ' ' << unsigned(dut.o_clear) << ' ' << unsigned(dut.o_debug)
                      << ' ' << unsigned(dut.loadUse) << ' ' << unsigned(dut.forward) << ' ' << unsigned(dut.externalInterrupt) << '\n';
            std::cout << "B " << cycle << ' ' << unsigned(dut.o_clear);
#define SRAM(p) \
            std::cout << ' ' << unsigned(dut.o_s_##p##_request_valid) << ' ' << dut.o_s_##p##_request_bits_address \
                      << ' ' << unsigned(dut.o_s_##p##_request_bits_machine) << ' ' << unsigned(dut.o_s_##p##_request_bits_write) \
                      << ' ' << dut.o_s_##p##_request_bits_data << ' ' << unsigned(dut.o_s_##p##_request_bits_mask) \
                      << ' ' << unsigned(dut.o_s_##p##_request_bits_size) << ' ' << unsigned(dut.o_s_##p##_request_bits_operation) \
                      << ' ' << unsigned(dut.o_s_##p##_response_ready) << ' ' << unsigned(dut.o_s_##p##_request_ready) \
                      << ' ' << unsigned(dut.o_s_##p##_response_valid) << ' ' << (dut.o_s_##p##_response_valid ? dut.o_s_##p##_response_bits_data : 0) \
                      << ' ' << unsigned(dut.o_s_##p##_response_valid && dut.o_s_##p##_response_bits_fault)
            SRAM(instruction);
            SRAM(data);
            SRAM(debug);
            SRAM(competitor);
#undef SRAM
            std::cout << ' ' << unsigned(dut.o_sram_read) << ' '
                      << ((dut.o_sram_read || dut.o_sram_mask) ? dut.o_sram_address : 0) << ' '
                      << unsigned(dut.o_sram_mask) << ' ' << (dut.o_sram_mask ? dut.o_sram_data : 0) << '\n';
            auto native = [&](unsigned index, char name, bool valid, bool ready, std::array<uint32_t, 7> request,
                              bool rv, bool rr, uint32_t data, bool fault) {
                auto &port = ports[index];
                if (port.held && (!valid || request != port.request)) throw std::runtime_error("Changed blocked native request");
                bool first = valid && !port.held;
                port.held = valid && !ready;
                port.request = request;
                if (rv && rr) {
                    if (!port.active) throw std::runtime_error("Unowned native response");
                    port.active = false;
                    std::cout << "S " << cycle << ' ' << name << ' ' << data << ' ' << fault << '\n';
                }
                if (first) {
                    std::cout << "P " << cycle << ' ' << name;
                    for (auto part : request) std::cout << ' ' << part;
                    std::cout << '\n';
                }
                if (valid && ready) {
                    if (port.active) throw std::runtime_error("Overlapping native owner");
                    port.active = true;
                    std::cout << "Q " << cycle << ' ' << name;
                    for (auto part : request) std::cout << ' ' << part;
                    std::cout << '\n';
                }
            };
#define NATIVE(index, tag, p) native(index, tag, dut.o_##p##_request_valid, dut.o_##p##_request_ready, \
    {dut.o_##p##_request_bits_address, dut.o_##p##_request_bits_write, dut.o_##p##_request_bits_data, \
     dut.o_##p##_request_bits_mask, dut.o_##p##_request_bits_size, dut.o_##p##_request_bits_machine, dut.o_##p##_request_bits_operation}, \
    dut.o_##p##_response_valid, dut.o_##p##_response_ready, dut.o_##p##_response_bits_data, dut.o_##p##_response_bits_fault)
            NATIVE(0, 'I', i);
            NATIVE(1, 'D', d);
            NATIVE(2, 'C', console);
            NATIVE(3, 'T', timer);
#undef NATIVE
            std::array<uint32_t, 7> arPayload{dut.axi_ar_bits_address, dut.axi_ar_bits_protection};
            if (axi.held && (!dut.axi_ar_valid || arPayload != axi.request)) throw std::runtime_error("Changed blocked AXI read");
            axi.held = dut.axi_ar_valid && !dut.axi_ar_ready;
            axi.request = arPayload;
            if (dut.axi_r_valid && dut.axi_r_ready) {
                if (!readActive) throw std::runtime_error("Unowned AXI response");
                std::cout << "A " << cycle << " R " << readData << ' ' << (readFault ? 3 : 0) << '\n';
                readActive = false;
            }
            if (dut.axi_ar_valid && dut.axi_ar_ready) {
                if (readActive) throw std::runtime_error("Overlapping AXI read");
                readActive = true;
                readFault = dut.axi_ar_bits_address >= 65536 || (dut.axi_ar_bits_address & 3);
                readData = rom[dut.axi_ar_bits_address];
                readDue = cycle + 1 + (delay ? random() % delay : 0);
                std::cout << "A " << cycle << " AR " << dut.axi_ar_bits_address << ' ' << unsigned(dut.axi_ar_bits_protection) << '\n';
            }
            if (dut.axi_aw_valid || dut.axi_w_valid) throw std::runtime_error("Atomic SRAM write reached AXI ROM");
            if (dut.competitor_response_valid && dut.competitor_response_ready) {
                if (!compActive) throw std::runtime_error("Unowned competitor response");
                if (compSignature) {
                    std::cout << "V " << cycle << ' ' << comp.address << ' ' << dut.competitor_response_bits_data
                              << ' ' << unsigned(dut.competitor_response_bits_fault) << '\n';
                    ++signatureIndex;
                }
                compActive = compSignature = false;
            }
            if (dut.competitor_request_valid && dut.competitor_request_ready) {
                if (compActive) throw std::runtime_error("Overlapping competitor request");
                compOffered = false;
                compActive = true;
                compReadyCycle = cycle + comp.hold;
            }
            bool debugAdvance = false;
            if (dut.retire_valid) {
                std::cout << "R " << cycle << ' ' << dut.retire_pc << ' ' << dut.retire_word << ' ' << dut.retire_nextPc
                          << ' ' << unsigned(dut.retire_rd) << ' ' << unsigned(dut.retire_writes) << ' ' << dut.retire_value
                          << ' ' << unsigned(dut.retire_trap) << ' ' << dut.retire_cause << ' ' << dut.retire_tval
                          << ' ' << unsigned(dut.retire_userMode) << '\n';
                if (competitorIndex < competitors.size() && dut.retire_pc == competitors[competitorIndex].trigger) {
                    if (compOffered || compActive) throw std::runtime_error("Competitor trigger overlapped a transaction");
                    comp = competitors[competitorIndex++];
                    compOffered = true;
                }
                if (interruptIndex < interrupts.size() && dut.retire_pc == interrupts[interruptIndex]) {
                    externalInterrupt = true;
                    ++interruptIndex;
                }
                if (dut.retire_pc == done && !completed) { completed = true; completionCycle = cycle; }
                debugAdvance = action.kind == 0 && dut.retire_pc == action.address;
            }
            if (dut.interrupt_valid) {
                std::cout << "N " << cycle << ' ' << dut.interrupt_pc << ' ' << dut.interrupt_target << ' ' << dut.interrupt_cause << '\n';
                externalInterrupt = false;
            }
            if (dut.transmit_valid) throw std::runtime_error("Unexpected atomic workload console output");
            if (dut.dmi_request_valid && dut.dmi_request_ready) {
                if (dmiActive) throw std::runtime_error("Overlapping DMI owner");
                dmiActive = true;
                currentSequence = sequence++;
                std::cout << "J " << cycle << ' ' << currentSequence << ' ' << debugIndex << ' '
                          << unsigned(dut.dmi_request_bits_address) << ' ' << unsigned(dut.dmi_request_bits_op)
                          << ' ' << dut.dmi_request_bits_data << '\n';
                if (dut.dmi_request_bits_address == 0x10 && dut.dmi_request_bits_op == 2 &&
                    (dut.dmi_request_bits_data & 2) && competitorIndex < competitors.size() &&
                    competitors[competitorIndex].trigger == 0xFFFFFFFF) {
                    if (compOffered || compActive) throw std::runtime_error("Reset competitor overlapped another request");
                    comp = competitors[competitorIndex++];
                    compOffered = true;
                }
            }
            const std::array<uint32_t, 2> dmiResponse{dut.dmi_response_bits_status, dut.dmi_response_bits_data};
            if (dmiHeld && (!dut.dmi_response_valid || dmiResponse != previousDmi)) throw std::runtime_error("DMI response changed under backpressure");
            dmiHeld = dut.dmi_response_valid && !dut.dmi_response_ready;
            previousDmi = dmiResponse;
            if (dut.dmi_response_valid && dut.dmi_response_ready) {
                if (!dmiActive) throw std::runtime_error("Unowned DMI response");
                std::cout << "K " << cycle << ' ' << currentSequence << ' ' << dmiResponse[0] << ' ' << dmiResponse[1] << '\n';
                dmiActive = false;
                debugAdvance = action.kind != 3 || (dmiResponse[1] & action.mask) == action.value;
            }
            if (action.kind == 4) debugAdvance = cycle - debugStart >= action.value;
            dut.clock = 1;
            dut.eval();
            if (debugAdvance) {
                std::cout << "L " << cycle << ' ' << debugIndex << '\n';
                ++debugIndex;
                debugStart = cycle + 1;
            }
            if (completed && cycle >= completionCycle + 8 && !readActive && !ports[0].active && !ports[1].active &&
                !ports[2].active && !ports[3].active && !compActive && !compOffered && signatureIndex == signatures.size()) {
                if (competitorIndex != competitors.size()) throw std::runtime_error("Missing competitor trigger");
                if (interruptIndex != interrupts.size() || externalInterrupt) throw std::runtime_error("Missing interrupt completion");
                if (debugIndex != debugActions.size() || dmiActive) throw std::runtime_error("Missing DMI completion");
                std::cout << "F " << cycle + 1 << '\n';
                finished = true;
                break;
            }
        }
        if (!finished) throw std::runtime_error("Atomic platform execution timeout");
        dut.final();
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
