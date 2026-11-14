// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
// Reuse the DMI/AXI driver without executing its external-memory scenarios.
#define main sba_platform_existing_main
#include "platform_sim.cpp"
#undef main
#include <string>

static uint32_t widthMask(unsigned size) {
    return size == 2 ? 0xffffffffu : (1u << (8u << size)) - 1;
}

static uint32_t abstractMemory(Simulation &sim, bool write, uint32_t address, unsigned size,
                               uint32_t value = 0, unsigned expectedError = 0) {
    sim.poll(0x16, 1u << 12, 0);
    sim.dmi(2, 5, address);
    if (write) sim.dmi(2, 4, value);
    sim.dmi(2, 0x17, 0x02000000u | (size << 20) | (write ? 1u << 16 : 0));
    sim.poll(0x16, 1u << 12, 0);
    const unsigned error = (sim.dmi(1, 0x16) >> 8) & 7;
    const uint32_t result = sim.dmi(1, 4);
    std::cout << "M " << unsigned(write) << ' ' << address << ' ' << size << ' ' << value
              << ' ' << result << ' ' << error << '\n';
    require(error == expectedError, "Abstract local-memory error differs");
    if (error) sim.dmi(2, 0x16, 0x700);
    return result;
}

static void checkBank(Simulation &sim, uint32_t base, uint32_t bytes) {
    for (unsigned size = 0; size < 3; ++size) {
        for (unsigned end = 0; end < 2; ++end) {
            const uint32_t word = end ? base + bytes - 4 : base;
            for (unsigned lane = 0; lane < 4; lane += 1u << size) {
                const uint32_t address = word + lane, bits = widthMask(size);
                const uint32_t first = (0xa5b6c7d8u ^ address) & bits;
                const uint32_t second = (0x71395badu ^ address) & bits;
                const uint32_t mask = bits << (lane * 8);
                sim.access(true, word, 2, 0x12345678);
                sim.access(true, address, size, first);
                require(abstractMemory(sim, false, address, size) == first, "SBA write is invisible to abstract memory");
                require(abstractMemory(sim, false, word, 2) == ((0x12345678u & ~mask) | (first << (lane * 8))),
                        "SBA masked write changed another lane");
                abstractMemory(sim, true, address, size, second);
                require(sim.access(false, address, size) == second, "Abstract write is invisible to SBA");
                require(sim.access(false, word, 2) == ((0x12345678u & ~mask) | (second << (lane * 8))),
                        "Abstract masked write changed another lane");
                std::cout << "T " << base << ' ' << address << ' ' << size << '\n';
            }
        }
    }
    // The runner verifies that these end addresses are unmapped in this test map.
    const uint32_t end = base + bytes;
    sim.dmi(2, 0x38, (2u << 17) | (1u << 20));
    sim.dmi(2, 0x39, end);
    sim.poll(0x38, 1u << 21, 0);
    require((sim.dmi(1, 0x38) & 0x7000) == 0x2000, "Unmapped local boundary did not fault through SBA");
    sim.dmi(2, 0x38, (2u << 17) | 0x7000);
    abstractMemory(sim, false, end, 2, 0, 5);
}

static void setPc(Simulation &sim, uint32_t pc) {
    sim.dmi(2, 4, pc);
    sim.dmi(2, 0x17, 0x002307b1);
    sim.poll(0x16, 1u << 12, 0);
    require(!(sim.dmi(1, 0x16) & 0x700), "DPC write failed");
    sim.dmi(2, 0x17, 0x002207b1);
    sim.poll(0x16, 1u << 12, 0);
    require(!(sim.dmi(1, 0x16) & 0x700) && sim.dmi(1, 4) == pc, "DPC readback differs");
}

static void observeLocal(Simulation &sim, std::array<unsigned, 4> &counts) {
    sim.prepare();
    counts[0] += sim.dut.o_it_i;
    counts[1] += sim.dut.o_it_d;
    counts[2] += sim.dut.o_dt_i;
    counts[3] += sim.dut.o_dt_d;
    sim.advance();
}

int main(int argc, char **argv) {
    try {
        require(argc == 7, "Expected ROM image, local code and two base/size pairs");
        Simulation sim(argv[1]);
        const uint32_t itcm = std::stoul(argv[3]), isize = std::stoul(argv[4]);
        const uint32_t dtcm = std::stoul(argv[5]), dsize = std::stoul(argv[6]);
        sim.halt();
        std::cout << "P halted " << sim.cycle << '\n';
        checkBank(sim, itcm, isize);
        checkBank(sim, dtcm, dsize);
        std::cout << "P code " << sim.cycle << '\n';
        std::ifstream code(argv[2]);
        uint32_t address, value, firstCode = 0;
        while (code >> std::hex >> address >> value) {
            if (address == itcm) firstCode = value;
            sim.access(true, address, 2, value);
        }
        require(code.eof(), "Malformed local program image");
        sim.access(true, dtcm + 0x100, 2, 0);
        setPc(sim, itcm);
        sim.dmi(2, 0x10, 0x40000001);
        sim.poll(0x11, 0xc00, 0xc00);
        sim.dmi(2, 0x10, 1);
        std::cout << "P running " << sim.cycle << '\n';
        std::array<unsigned, 4> local{};
        for (unsigned cycle = 0; cycle < 400; ++cycle) observeLocal(sim, local);
        uint32_t last = 0;
        for (unsigned iteration = 0; iteration < 4; ++iteration) {
            last = 0x5a123400u + iteration;
            for (auto base : {itcm, dtcm}) {
                sim.access(true, base + 0x200, 2, last);
                require(sim.access(false, base + 0x200, 2) == last, "Concurrent local SBA access differs");
            }
        }
        for (unsigned cycle = 0; cycle < 400; ++cycle) observeLocal(sim, local);
        require(local[0] && local[3], "Local instruction fetch and data operations were not reached");
        require(sim.access(false, dtcm + 0x100, 2) != 0, "Local loop made no data progress");
        std::cout << "L " << local[0] << ' ' << local[1] << ' ' << local[2] << ' ' << local[3] << '\n';

        std::cout << "P reset " << sim.cycle << '\n';
        sim.delay = 250;
        const unsigned before = sim.resets;
        sim.dmi(2, 0x38, (2u << 17) | (1u << 20));
        sim.dmi(2, 0x39, 4);
        require(sim.sbaActive, "Reset test missed the external SBA owner");
        sim.dmi(2, 0x10, 0xb);
        sim.dmi(2, 0x10, 1);
        require(sim.resets == before, "Warm reset preceded the pending SBA response");
        while (sim.sbaActive) sim.advance();
        for (unsigned cycle = 0; cycle < 400 && sim.resets == before; ++cycle) sim.advance();
        require(sim.resets == before + 1, "Warm reset did not follow SBA drain");
        sim.poll(0x11, 0x300, 0x300);
        require(sim.dmi(1, 0x3c) == 0x13, "Warm reset discarded the SBA read result");
        sim.delay = 5;
        std::cout << "P retained " << sim.cycle << '\n';
        for (auto base : {itcm, dtcm}) {
            require(sim.access(false, base + 0x200, 2) == last, "Warm reset cleared local storage");
            require(abstractMemory(sim, false, base + 0x200, 2) == last, "Post-reset abstract visibility differs");
        }
        require(sim.access(false, itcm, 2) == firstCode, "Warm reset changed executable local storage");
        require(sim.requests == sim.completions && !sim.sbaActive && !sim.held, "Local SBA traffic did not drain");
        std::cout << "F " << sim.cycle << ' ' << sim.requests << ' ' << sim.completions << ' ' << sim.resets << '\n';
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
