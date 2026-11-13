// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VSbaPlatformBench.h"
#include "verilated.h"
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>

static void require(bool condition, const char *message) {
    if (!condition) throw std::runtime_error(message);
}

class Simulation {
public:
    VSbaPlatformBench dut;
    std::map<uint32_t, uint32_t> memory;
    uint64_t cycle = 0, due = 0, writeDue = 0;
    bool readActive = false, aw = false, w = false, b = false;
    uint32_t readData = 0, writeAddress = 0, writeData = 0, strobe = 0;
    unsigned delay = 5, resets = 0, requests = 0, completions = 0;
    bool readFault = false, writeFault = false, sbaActive = false, held = false;
    bool previousReset = false;
    std::array<uint32_t, 7> previous{};

    Simulation(const char *path) {
        std::ifstream image(path);
        uint32_t address, value;
        while (image >> std::hex >> address >> value) memory[address] = value;
        require(image.eof(), "Malformed ROM image");
        dut.reset = 1;
        dut.clock = 0;
        dut.tick = dut.externalInterrupt = 0;
        dut.transmit_ready = 1;
        dut.dmi_request_valid = dut.dmi_response_ready = 0;
        dut.dmi_request_bits_address = dut.dmi_request_bits_data = dut.dmi_request_bits_op = 0;
        dut.axi_ar_ready = dut.axi_aw_ready = dut.axi_w_ready = 0;
        dut.axi_r_valid = dut.axi_b_valid = 0;
        dut.axi_r_bits_data = dut.axi_r_bits_response = dut.axi_b_bits_response = 0;
#if DITDAH_E2_SBA_ATOMIC
        dut.competitor_request_valid = 0;
        dut.competitor_response_ready = 1;
        dut.competitor_request_bits_address = dut.competitor_request_bits_data = 0;
        dut.competitor_request_bits_machine = dut.competitor_request_bits_write = 0;
        dut.competitor_request_bits_mask = dut.competitor_request_bits_size = 0;
        dut.competitor_request_bits_operation = 0;
#endif
        for (unsigned edge = 0; edge < 4; ++edge) { dut.clock = edge & 1; dut.eval(); }
        dut.reset = 0;
    }

    bool readable(uint32_t address) const {
        return address < 65536 || (address >= 0x20000000 && address < 0x20010000);
    }

    void prepare() {
        require(cycle < 200000, "Platform test cycle limit exceeded");
        dut.clock = 0;
        dut.axi_ar_ready = !readActive && cycle % 3 != 0;
        dut.axi_aw_ready = !aw && !b && cycle % 4 != 0;
        dut.axi_w_ready = !w && !b && cycle % 5 != 0;
        dut.axi_r_valid = readActive && cycle >= due;
        dut.axi_r_bits_data = readData;
        dut.axi_r_bits_response = readFault ? 3 : 0;
        dut.axi_b_valid = b && cycle >= writeDue;
        dut.axi_b_bits_response = writeFault ? 3 : 0;
        dut.eval();
    }

    void advance() {
        prepare();
        const bool reset = dut.o_systemReset;
        if (reset && !previousReset) ++resets;
        previousReset = reset;
        require(!reset || !sbaActive, "Warm reset discarded an accepted SBA transfer");
        const std::array<uint32_t, 7> payload{dut.o_s_request_bits_address,
            dut.o_s_request_bits_machine, dut.o_s_request_bits_write,
            dut.o_s_request_bits_data, dut.o_s_request_bits_mask,
            dut.o_s_request_bits_size, dut.o_s_request_bits_operation};
        require(!held || (dut.o_s_request_valid && payload == previous), "SBA offer changed under backpressure");
        held = dut.o_s_request_valid && !dut.o_s_request_ready;
        previous = payload;
        if (dut.o_s_response_valid && dut.o_s_response_ready) {
            require(sbaActive, "Unowned SBA platform response");
            sbaActive = false;
            ++completions;
            std::cout << "S " << cycle << ' ' << dut.o_s_response_bits_data << ' '
                      << unsigned(dut.o_s_response_bits_fault) << '\n';
        }
        if (dut.o_s_request_valid && dut.o_s_request_ready) {
            require(!sbaActive, "Overlapping SBA platform transactions");
            sbaActive = true;
            ++requests;
            std::cout << "Q " << cycle;
            for (auto item : payload) std::cout << ' ' << item;
            std::cout << '\n';
        }
        if (dut.retire_valid) {
            std::cout << "R " << cycle << ' ' << dut.retire_pc << ' ' << dut.retire_word
                      << ' ' << unsigned(dut.retire_rd) << ' ' << dut.retire_value
                      << ' ' << unsigned(dut.retire_trap) << '\n';
            require(!dut.retire_trap, "Unexpected platform firmware trap");
        }
        if (reset) std::cout << "N " << cycle << '\n';
        if (dut.o_clear) std::cout << "C " << cycle << '\n';
        if (dut.axi_r_valid && dut.axi_r_ready) readActive = false;
        if (dut.axi_b_valid && dut.axi_b_ready) b = false;
        if (dut.axi_ar_valid && dut.axi_ar_ready) {
            const uint32_t address = dut.axi_ar_bits_address;
            require(!readActive, "Overlapping AXI reads");
            readActive = true;
            readFault = !readable(address);
            require(readFault || memory.count(address), "Read from uninitialized external memory");
            readData = readFault ? 0 : memory.at(address);
            due = cycle + delay + 1;
        }
        if (dut.axi_aw_valid && dut.axi_aw_ready) { aw = true; writeAddress = dut.axi_aw_bits_address; }
        if (dut.axi_w_valid && dut.axi_w_ready) {
            w = true;
            writeData = dut.axi_w_bits_data;
            strobe = dut.axi_w_bits_strobe;
        }
        if (aw && w && !b) {
            writeFault = writeAddress < 0x20000000 || writeAddress >= 0x20010000;
            if (!writeFault) {
                auto &value = memory[writeAddress];
                for (unsigned lane = 0; lane < 4; ++lane) {
                    if (!(strobe & (1u << lane))) continue;
                    const uint32_t mask = 255u << (8 * lane);
                    value = (value & ~mask) | (writeData & mask);
                }
            }
            aw = w = false;
            b = true;
            writeDue = cycle + delay + 1;
        }
        dut.clock = 1;
        dut.eval();
        ++cycle;
    }

    uint32_t dmi(unsigned op, unsigned address, uint32_t data = 0) {
        dut.dmi_request_valid = 1;
        dut.dmi_request_bits_op = op;
        dut.dmi_request_bits_address = address;
        dut.dmi_request_bits_data = data;
        dut.dmi_response_ready = 0;
        for (;;) {
            prepare();
            const bool accepted = dut.dmi_request_ready;
            advance();
            if (accepted) break;
        }
        dut.dmi_request_valid = 0;
        unsigned stalls = 0;
        for (;;) {
            dut.dmi_response_ready = stalls++ > 2;
            prepare();
            const bool complete = dut.dmi_response_valid && dut.dmi_response_ready;
            const uint32_t result = dut.dmi_response_bits_data;
            require(!complete || dut.dmi_response_bits_status == 0, "Failed DMI response");
            advance();
            if (complete) {
                dut.dmi_response_ready = 0;
                return result;
            }
        }
    }

    void poll(unsigned address, uint32_t mask, uint32_t expected) {
        for (unsigned count = 0; count < 1000; ++count) {
            if ((dmi(1, address) & mask) == expected) return;
        }
        throw std::runtime_error("DMI poll timed out");
    }

    uint32_t access(bool write, uint32_t address, unsigned size, uint32_t data = 0) {
        dmi(2, 0x38, (size << 17) | (!write ? 1u << 20 : 0));
        dmi(2, 0x39, address);
        if (write) dmi(2, 0x3c, data);
        poll(0x38, 1u << 21, 0);
        require(!(dmi(1, 0x38) & 0x407000), "Unexpected sticky SBA error");
        return dmi(1, 0x3c);
    }

    void word(uint32_t address, uint32_t expected) {
        for (unsigned count = 0; count < 1000; ++count) {
            if (access(false, address, 2) == expected) return;
        }
        throw std::runtime_error("Firmware memory handshake timed out");
    }

    void halt() {
        dmi(2, 0x10, 1);
        poll(0x10, 1, 1);
        dmi(2, 0x10, 0x80000001);
        poll(0x11, 0x300, 0x300);
    }

    void warmReset() {
        dmi(2, 0x10, 0xb);
        dmi(2, 0x10, 1);
        poll(0x11, 0x300, 0x300);
    }
};

int main(int argc, char **argv) {
    try {
        require(argc == 2, "Expected ROM image");
        Simulation sim(argv[1]);
        sim.halt();
        require(sim.dmi(1, 0x38) == 0x20040407, "SBA capability/reset value differs");
        sim.access(true, 0x20000000, 2, 0x11223344);
        sim.access(true, 0x20000040, 2, 0);
        require(sim.access(false, 0x20000000, 2) == 0x11223344, "SBA platform word mismatch");
        sim.access(true, 0x20000001, 0, 0xaa);
        sim.access(true, 0x20000002, 1, 0xbbcc);
        require(sim.access(false, 0x20000000, 2) == 0xbbccaa44, "SBA lane writes corrupted memory");
        require(sim.access(false, 0x20000001, 0) == 0xaa, "SBA byte read mismatch");
        require(sim.access(false, 0x20000002, 1) == 0xbbcc, "SBA halfword read mismatch");
        sim.dmi(2, 0x38, 2u << 17);
        sim.dmi(2, 0x39, 0);
        sim.dmi(2, 0x3c, 0xffffffff);
        sim.poll(0x38, 1u << 21, 0);
        require((sim.dmi(1, 0x38) & 0x7000) == 0x2000, "ROM write did not report a bus fault");
        sim.dmi(2, 0x38, (2u << 17) | 0x7000);
        require(sim.access(false, 0, 2) == 0x13, "Rejected ROM write changed the image");

        // Keep a real ROM read pending while ndmreset is requested.
        sim.delay = 250;
        const unsigned resetBefore = sim.resets;
        sim.dmi(2, 0x38, (2u << 17) | (1u << 20));
        sim.dmi(2, 0x39, 0);
        require(sim.sbaActive, "Warm reset test missed the accepted SBA interval");
        sim.dmi(2, 0x10, 0xb);
        sim.dmi(2, 0x10, 1);
        require(sim.resets == resetBefore, "Warm reset entered before the delayed response");
        while (sim.sbaActive) sim.advance();
        for (unsigned n = 0; n < 400 && sim.resets == resetBefore; ++n) sim.advance();
        require(sim.resets == resetBefore + 1, "Drained SBA did not permit warm reset");
        sim.poll(0x11, 0x300, 0x300);
        require(sim.dmi(1, 0x3c) == 0x13, "ndmreset reset the SBA register bank");

        // Deactivation keeps the physical owner, and reactivation waits for it.
        sim.dmi(2, 0x39, 4);
        require(sim.sbaActive, "Epoch test missed the accepted SBA interval");
        sim.dmi(2, 0x10, 0);
        sim.dmi(2, 0x10, 1);
        require(!(sim.dmi(1, 0x10) & 1), "DM reactivated before the old bus owner drained");
        sim.poll(0x10, 1, 1);
        require(sim.dmi(1, 0x38) == 0x20040407 && sim.dmi(1, 0x39) == 0 && sim.dmi(1, 0x3c) == 0,
                "Discarded completion contaminated the new DM activation");
        sim.delay = 5;
        sim.halt();

#if DITDAH_E2_SBA_ATOMIC
        for (unsigned conflict = 0; conflict < 2; ++conflict) {
            sim.warmReset();
            sim.access(true, 0x20000000, 2, 0x11223344);
            sim.access(true, 0x20000040, 2, 0);
            sim.access(true, 0x20000080, 2, 0xffffffff);
            sim.dmi(2, 0x10, 0x40000001);
            sim.poll(0x11, 0xc00, 0xc00);
            sim.access(true, 0x20000040, 2, 1);
            sim.word(0x20000040, 2);
            const uint64_t interval = sim.cycle;
            if (conflict) sim.access(true, 0x20000001, 0, 0xaa);
            else sim.access(true, 0x20000010, 2, 0x12345678);
            sim.access(true, 0x20000040, 2, 3);
            sim.word(0x20000080, conflict ? 1 : 0);
            require(sim.access(false, 0x20000084, 2) == 0x11223344, "LR data changed across SBA writes");
            require(sim.access(false, 0x20000000, 2) == (conflict ? 0x1122aa44u : 0x55667788u),
                    "SBA reservation invalidation or SC memory effect differs");
            std::cout << "A " << conflict << ' ' << interval << ' ' << sim.cycle << '\n';
            sim.halt();
        }
#endif
        require(sim.requests == sim.completions && !sim.sbaActive && !sim.held, "Platform SBA traffic did not drain");
        std::cout << "F " << sim.cycle << ' ' << sim.requests << ' ' << sim.completions << ' ' << sim.resets << '\n';
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
