// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VPlatformBench.h"
#include "verilated.h"
#include "rvfi_trace.hpp"
#include <cstdlib>
#include "inactive_debug.hpp"
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

struct Transfer {
    bool active = false, held = false;
    std::array<uint32_t, 6> request{};
    std::array<uint32_t, 6> accepted{};
    uint64_t offerId = 0, acceptedId = 0, acceptedCycle = 0;
};

int main(int argc, char **argv) {
    try {
        if (argc < 5 || argc > 7)
            throw std::runtime_error("Expected image seed delay completion-pc [bank-map [instruction-tail]]");
        const bool instructionTail = argc == 7 && std::string(argv[6]) == "instruction-tail";
        if (argc == 7 && !instructionTail) throw std::runtime_error("Unknown platform completion policy");
        VerilatedContext context;
        context.commandArgs(argc, argv);
        VPlatformBench dut{&context};
        std::ofstream rvfi, rvfiInterrupts;
        if (const char *path = std::getenv("DITDAH_E2_RVFI_TRACE")) {
            rvfi.open(path);
            if (!rvfi) throw std::runtime_error("Cannot open retirement trace");
        }
        if (const char *path = std::getenv("DITDAH_E2_RVFI_INTERRUPTS")) {
            rvfiInterrupts.open(path);
            if (!rvfiInterrupts) throw std::runtime_error("Cannot open interrupt trace");
        }
        inactiveDebug(dut);
        std::ifstream file(argv[1]);
        uint64_t rom, romSize, ram, ramSize;
        if (!(file >> std::hex >> rom >> romSize >> ram >> ramSize))
            throw std::runtime_error("Missing platform memory bounds");
        std::vector<std::array<uint64_t, 3>> banks;
        if (argc >= 6) {
            std::ifstream bankFile(argv[5]);
            if (!bankFile) throw std::runtime_error("Cannot open bank map");
            std::array<uint64_t, 3> bank;
            while (bankFile >> std::hex >> bank[0] >> bank[1] >> bank[2]) banks.push_back(bank);
            if (!bankFile.eof()) throw std::runtime_error("Malformed bank map");
        }
        std::map<uint32_t, uint32_t> memory;
        uint32_t address, word;
        while (file >> std::hex >> address >> word) memory[address] = word;
        if (!file.eof()) throw std::runtime_error("Malformed program image");
        uint32_t state = std::stoul(argv[2]) + 1;
        const unsigned delay = std::stoul(argv[3]);
        const uint32_t done = std::stoul(argv[4]);
        auto random = [&]() { state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state; };
        auto allows = [&](uint32_t at, bool write) {
            for (const auto &bank : banks)
                if (at >= bank[0] && uint64_t(at) + 4 <= bank[0] + bank[1])
                    return !(at & 3) && bank[2];
            return !(at & 3) && ((at >= ram && uint64_t(at) + 4 <= ram + ramSize) ||
                (!write && at >= rom && uint64_t(at) + 4 <= rom + romSize));
        };
        bool ar = false, aw = false, w = false, b = false;
        uint32_t readData = 0, readAddress = 0, readProtection = 0;
        uint32_t writeAddress = 0, writeData = 0, strobe = 0;
        uint64_t readDue = 0, writeDue = 0;
        bool readFault = false, writeFault = false;
        std::array<Transfer, 4> ports{};
        std::array<Transfer, 3> axiHeld{};
        dut.reset = 1;
        dut.tick = dut.externalInterrupt = dut.transmit_ready = 0;
        dut.axi_aw_ready = dut.axi_w_ready = dut.axi_ar_ready = 0;
        dut.axi_b_valid = dut.axi_r_valid = 0;
        dut.axi_b_bits_response = dut.axi_r_bits_response = dut.axi_r_bits_data = 0;
        for (int edge = 0; edge < 4; ++edge) { dut.clock = edge & 1; dut.eval(); }
        dut.reset = 0;
        bool completed = false, finished = false;
        uint64_t completionCycle = 0;
        uint64_t instructionOffers = 0, instructionAccepted = 0, instructionCompleted = 0;
        uint64_t completionFrontier = 0;
        for (uint64_t cycle = 0; cycle < 2000000; ++cycle) {
            dut.clock = 0;
            dut.tick = cycle % 100 == 99;
            dut.transmit_ready = !delay || random() % 7 == 0;
            dut.axi_ar_ready = !ar && !aw && !w && !b && (!delay || random() % 3 == 0);
            dut.axi_aw_ready = !aw && !ar && !b && (!delay || random() % 4 == 0);
            dut.axi_w_ready = !w && !ar && !b && (!delay || random() % 5 == 0);
            dut.axi_r_valid = ar && cycle >= readDue;
            dut.axi_r_bits_data = readData;
            dut.axi_r_bits_response = readFault ? 3 : 0;
            dut.axi_b_valid = b && cycle >= writeDue;
            dut.axi_b_bits_response = writeFault ? 3 : 0;
            dut.eval();
            if ((dut.o_i_request_valid && dut.o_i_request_bits_operation) ||
                (dut.o_d_request_valid && dut.o_d_request_bits_operation))
                throw std::runtime_error("Atomic request requires the shared memory platform");
            if (completed && dut.o_d_request_valid)
                throw std::runtime_error("Data request after program completion");
            std::cout << "T " << cycle << ' ' << unsigned(dut.tick) << ' '
                      << unsigned(dut.transmit_ready) << ' ' << dut.timeValue << ' '
                      << unsigned(dut.timerInterrupt) << ' ' << unsigned(dut.softwareInterrupt)
                      << ' ' << unsigned(dut.sleeping) << '\n';
            auto native = [&](unsigned index, char name, bool valid, bool ready,
                              std::array<uint32_t, 6> request, bool rv, bool rr,
                              uint32_t value, bool fault) {
                auto &port = ports[index];
                if (port.held && (!valid || request != port.request))
                    throw std::runtime_error("Native request changed under backpressure");
                const bool first = valid && !port.held;
                port.held = valid && !ready;
                port.request = request;
                if (rv && rr) {
                    if (!port.active) throw std::runtime_error("Native response has no owner");
                    if (index == 0 && port.acceptedId != ++instructionCompleted)
                        throw std::runtime_error("Instruction response order changed");
                    port.active = false;
                    std::cout << "S " << cycle << ' ' << name << ' ' << value << ' ' << fault << '\n';
                }
                if (first && index < 2) {
                    if (index == 0) port.offerId = ++instructionOffers;
                    std::cout << "P " << cycle << ' ' << name;
                    for (auto item : request) std::cout << ' ' << item;
                    std::cout << '\n';
                }
                if (valid && ready) {
                    if (port.active) throw std::runtime_error("Native transaction overlapped");
                    port.active = true;
                    port.accepted = request;
                    port.acceptedCycle = cycle;
                    if (index == 0) {
                        port.acceptedId = port.offerId;
                        if (port.acceptedId != ++instructionAccepted)
                            throw std::runtime_error("Instruction acceptance order changed");
                    }
                    std::cout << "Q " << cycle << ' ' << name;
                    for (auto item : request) std::cout << ' ' << item;
                    std::cout << '\n';
                }
            };
#define OBSERVE(index, tag, p) native(index, tag, dut.o_##p##_request_valid, dut.o_##p##_request_ready, \
    {dut.o_##p##_request_bits_address, dut.o_##p##_request_bits_write, dut.o_##p##_request_bits_data, \
     dut.o_##p##_request_bits_mask, dut.o_##p##_request_bits_size, dut.o_##p##_request_bits_machine}, dut.o_##p##_response_valid, \
     dut.o_##p##_response_ready, dut.o_##p##_response_bits_data, dut.o_##p##_response_bits_fault)
            OBSERVE(0, 'I', i);
            OBSERVE(1, 'D', d);
            OBSERVE(2, 'C', console);
            OBSERVE(3, 'T', timer);
#undef OBSERVE
            auto stable = [&](unsigned index, bool valid, bool ready, std::array<uint32_t, 6> payload) {
                auto &previous = axiHeld[index];
                if (previous.held && (!valid || payload != previous.request))
                    throw std::runtime_error("AXI request changed under backpressure");
                previous.held = valid && !ready;
                previous.request = payload;
            };
            stable(0, dut.axi_ar_valid, dut.axi_ar_ready, {dut.axi_ar_bits_address, dut.axi_ar_bits_protection, 0, 0, 0});
            stable(1, dut.axi_aw_valid, dut.axi_aw_ready, {dut.axi_aw_bits_address, dut.axi_aw_bits_protection, 0, 0, 0});
            stable(2, dut.axi_w_valid, dut.axi_w_ready, {dut.axi_w_bits_data, dut.axi_w_bits_strobe, 0, 0, 0});
            if (dut.axi_r_valid && dut.axi_r_ready) {
                std::cout << "A " << cycle << " R " << readData << ' ' << (readFault ? 3 : 0) << '\n';
                ar = false;
            }
            if (dut.axi_b_valid && dut.axi_b_ready) {
                std::cout << "A " << cycle << " B " << (writeFault ? 3 : 0) << '\n';
                b = aw = w = false;
            }
            if (dut.axi_ar_valid && dut.axi_ar_ready) {
                if (ar || aw || w || b) throw std::runtime_error("AXI read overlapped another transfer");
                ar = true;
                readAddress = dut.axi_ar_bits_address;
                readProtection = dut.axi_ar_bits_protection;
                readFault = !allows(dut.axi_ar_bits_address, false);
                readData = memory[dut.axi_ar_bits_address];
                readDue = cycle + 1 + (delay ? random() % delay : 0);
                std::cout << "A " << cycle << " AR " << dut.axi_ar_bits_address << ' '
                          << unsigned(dut.axi_ar_bits_protection) << '\n';
            }
            if (dut.axi_aw_valid && dut.axi_aw_ready) {
                aw = true;
                writeAddress = dut.axi_aw_bits_address;
                std::cout << "A " << cycle << " AW " << writeAddress << ' '
                          << unsigned(dut.axi_aw_bits_protection) << '\n';
            }
            if (dut.axi_w_valid && dut.axi_w_ready) {
                w = true;
                writeData = dut.axi_w_bits_data;
                strobe = dut.axi_w_bits_strobe;
                std::cout << "A " << cycle << " W " << writeData << ' ' << strobe << '\n';
            }
            if (aw && w && !b) {
                b = true;
                writeDue = cycle + 1 + (delay ? random() % delay : 0);
                writeFault = !allows(writeAddress, true);
                if (!writeFault) {
                    auto &value = memory[writeAddress];
                    for (unsigned lane = 0; lane < 4; ++lane)
                        if (strobe & (1u << lane))
                            value = (value & ~(255u << (8 * lane))) | (writeData & (255u << (8 * lane)));
                }
            }
            if (dut.transmit_valid && dut.transmit_ready)
                std::cout << "X " << cycle << ' ' << unsigned(dut.transmit_bits) << '\n';
            if (rvfi.is_open()) writeRvfi(rvfi, dut, cycle);
            if (rvfiInterrupts.is_open()) writeRvfiInterrupt(rvfiInterrupts, dut, cycle);
            if (dut.retire_valid) {
                if (dut.interrupt_valid) throw std::runtime_error("Two architectural events in one cycle");
                std::cout << "R " << cycle << ' ' << dut.retire_pc << ' ' << dut.retire_word << ' '
                          << dut.retire_nextPc << ' ' << unsigned(dut.retire_rd) << ' '
                          << unsigned(dut.retire_writes) << ' ' << dut.retire_value << ' '
                          << unsigned(dut.retire_trap) << ' ' << dut.retire_cause << ' ' << dut.retire_tval << ' ' << unsigned(dut.retire_userMode) << '\n';
                if (dut.retire_pc == done) {
                    if (dut.retire_trap || dut.retire_word != 0x6f || dut.retire_nextPc != done)
                        throw std::runtime_error("Invalid platform completion instruction");
                    if (!completed) {
                        completed = true;
                        completionCycle = cycle;
                        completionFrontier = instructionOffers;
                    }
                }
            }
            if (dut.interrupt_valid)
                std::cout << "N " << cycle << ' ' << dut.interrupt_pc << ' ' << dut.interrupt_target
                          << ' ' << dut.interrupt_cause << '\n';
            dut.clock = 1;
            dut.eval();
            // A running terminal loop need not leave an instruction-port bubble.
            const bool frontierDrained = instructionCompleted >= completionFrontier;
            const bool instructionCut = instructionTail && frontierDrained &&
                (!ports[0].active || ports[0].acceptedId > completionFrontier) &&
                (!ports[0].held || ports[0].offerId > completionFrontier);
            if (completed && cycle >= completionCycle + 8 && (!ar || (instructionCut && (readProtection & 4))) &&
                !aw && !w && !b && (!ports[0].active || instructionCut) &&
                !ports[1].active && !ports[2].active && !ports[3].active && !dut.transmit_valid) {
                std::cout << "F " << cycle + 1 << '\n';
                if (instructionTail) {
                    const auto &port = ports[0];
                    std::cout << "J " << done << ' ' << completionCycle << ' ' << completionFrontier << ' '
                              << instructionOffers << ' ' << instructionAccepted << ' ' << instructionCompleted << ' '
                              << (port.active ? port.acceptedId : 0) << ' ' << (port.active ? port.acceptedCycle : 0);
                    for (auto value : port.accepted) std::cout << ' ' << (port.active ? value : 0);
                    std::cout << ' ' << (port.held ? port.offerId : 0);
                    for (auto value : port.request) std::cout << ' ' << (port.held ? value : 0);
                    std::cout << ' ' << ar << ' ' << (ar ? readAddress : 0) << ' ' << (ar ? readProtection : 0)
                              << ' ' << axiHeld[2].held << ' '
                              << (axiHeld[2].held ? axiHeld[2].request[0] : 0) << ' '
                              << (axiHeld[2].held ? axiHeld[2].request[1] : 0) << '\n';
                }
                finished = true;
                break;
            }
        }
        if (!finished) throw std::runtime_error("Platform execution timeout");
        for (auto [location, value] : memory) std::cout << "W " << location << ' ' << value << '\n';
        dut.final();
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
