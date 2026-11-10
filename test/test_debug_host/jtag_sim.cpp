// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VDitDahE2.h"
#include "verilated.h"
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

struct Request {
    uint32_t address = 0, data = 0, mask = 0, size = 0;
    bool write = false, machine = false;
    bool operator==(const Request &other) const {
        return address == other.address && data == other.data && mask == other.mask &&
               size == other.size && write == other.write && machine == other.machine;
    }
};

struct Port {
    bool active = false, held = false;
    Request request{}, previous{};
    uint64_t due = 0;
    uint32_t data = 0;
};

class TapObserver {
    enum State {
        reset, idle, selectDr, captureDr, shiftDr, exit1Dr, pauseDr, exit2Dr, updateDr,
        selectIr, captureIr, shiftIr, exit1Ir, pauseIr, exit2Ir, updateIr
    };
    State state = reset;
    uint64_t shifted = 0;
    unsigned bits = 0, instruction = 1;

    State next(State current, bool tms) const {
        switch (current) {
        case reset: return tms ? reset : idle;
        case idle: return tms ? selectDr : idle;
        case selectDr: return tms ? selectIr : captureDr;
        case captureDr: return tms ? exit1Dr : shiftDr;
        case shiftDr: return tms ? exit1Dr : shiftDr;
        case exit1Dr: return tms ? updateDr : pauseDr;
        case pauseDr: return tms ? exit2Dr : pauseDr;
        case exit2Dr: return tms ? updateDr : shiftDr;
        case updateDr: return tms ? selectDr : idle;
        case selectIr: return tms ? reset : captureIr;
        case captureIr: return tms ? exit1Ir : shiftIr;
        case shiftIr: return tms ? exit1Ir : shiftIr;
        case exit1Ir: return tms ? updateIr : pauseIr;
        case pauseIr: return tms ? exit2Ir : pauseIr;
        case exit2Ir: return tms ? updateIr : shiftIr;
        case updateIr: return tms ? selectDr : idle;
        }
        throw std::runtime_error("Invalid JTAG observer state");
    }

public:
    void resetNow() {
        state = reset;
        instruction = 1;
        shifted = 0;
        bits = 0;
    }

    void clock(bool tms, bool tdi, uint64_t cycle, std::ostream &trace) {
        if (state == captureDr || state == captureIr) {
            shifted = 0;
            bits = 0;
        }
        if (state == shiftDr || state == shiftIr) {
            if (bits < 64) shifted |= uint64_t(tdi) << bits;
            ++bits;
        }
        if (state == updateIr && bits == 5) instruction = shifted & 31;
        if (state == updateDr && instruction == 0x11 && bits == 41) {
            const unsigned operation = shifted & 3;
            const uint32_t data = (shifted >> 2) & 0xffffffffULL;
            const unsigned address = (shifted >> 34) & 0x7f;
            if (operation == 1 || operation == 2)
                trace << "J " << cycle << ' ' << address << ' ' << operation << ' ' << data << '\n';
        }
        state = next(state, tms);
        if (state == reset) instruction = 1;
    }
};

static void sendByte(int socket, char value) {
    const char *buffer = &value;
    size_t remaining = 1;
    while (remaining) {
        const auto count = send(socket, buffer, remaining, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw std::runtime_error("Remote bitbang connection closed during a reply");
        buffer += count;
        remaining -= count;
    }
}

int main(int argc, char **argv) {
    int listener = -1, client = -1;
    try {
        if (argc < 5 || argc > 6)
            throw std::runtime_error("Expected image seed delay cycle-limit and optional bitbang-port");
        VerilatedContext context;
        context.commandArgs(argc, argv);
        VDitDahE2 dut{&context};
        std::cout.setf(std::ios::unitbuf);
        std::map<uint32_t, uint32_t> memory;
        std::ifstream image(argv[1]);
        if (!image) throw std::runtime_error("Cannot open program image");
        uint32_t address, word;
        while (image >> std::hex >> address >> word) {
            if (address & 3) throw std::runtime_error("Program image address is not aligned");
            memory[address] = word;
        }
        if (!image.eof()) throw std::runtime_error("Malformed program image");
        uint32_t state = std::stoul(argv[2]) + 1;
        auto random = [&]() { state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state; };
        const unsigned delay = std::stoul(argv[3]);
        const uint64_t limit = std::stoull(argv[4]);
        const unsigned requestedPort = argc == 6 ? std::stoul(argv[5]) : 0;
        if (requestedPort > 65535) throw std::runtime_error("Invalid remote bitbang port");

        dut.clock = dut.jtag_tck = dut.jtag_tdi = 0;
        dut.reset = 1;
        dut.jtag_trstN = 0;
        dut.jtag_tms = 1;
        dut.instruction_request_ready = dut.data_request_ready = 0;
        dut.instruction_response_valid = dut.data_response_valid = 0;
        dut.instruction_response_bits_data = dut.data_response_bits_data = 0;
        dut.instruction_response_bits_fault = dut.data_response_bits_fault = 0;
        dut.interrupts_software = dut.interrupts_timer = dut.interrupts_external = 0;
        dut.timeValue = 0;
        for (int edge = 0; edge < 4; ++edge) {
            dut.clock = edge & 1;
            dut.eval();
        }
        dut.clock = 0;
        dut.jtag_trstN = 1;
        dut.eval();

        listener = socket(AF_INET, SOCK_STREAM, 0);
        if (listener < 0) throw std::runtime_error("Cannot create remote bitbang socket");
        int enabled = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        endpoint.sin_port = htons(requestedPort);
        if (bind(listener, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) ||
            listen(listener, 1)) throw std::runtime_error("Cannot listen for remote bitbang");
        socklen_t length = sizeof(endpoint);
        if (getsockname(listener, reinterpret_cast<sockaddr *>(&endpoint), &length))
            throw std::runtime_error("Cannot determine remote bitbang port");
        std::cout << "B " << ntohs(endpoint.sin_port) << '\n';
        do client = accept(listener, nullptr, nullptr);
        while (client < 0 && errno == EINTR);
        if (client < 0) throw std::runtime_error("Cannot accept remote bitbang connection");
        close(listener);
        listener = -1;
        enabled = 1;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        std::signal(SIGPIPE, SIG_IGN);

        TapObserver tap;
        Port instruction, data;
        uint64_t cycle = 0, externalResets = 0, debugResets = 0, tdoSamples = 0, tdoEnabledSamples = 0;
        bool previousExternal = true, previousDebug = false, finished = false;
        std::deque<unsigned char> pending;
        for (; cycle < limit && !finished; ++cycle) {
            for (;;) {
                char buffer[4096];
                const auto count = recv(client, buffer, sizeof(buffer), MSG_DONTWAIT);
                if (count < 0 && errno == EINTR) continue;
                if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                if (count < 0) throw std::runtime_error(std::string("Remote bitbang receive failed: ") + std::strerror(errno));
                if (!count) {
                    finished = true;
                    break;
                }
                pending.insert(pending.end(), buffer, buffer + count);
            }
            if (finished) break;
            if (!pending.empty()) {
                const unsigned char value = pending.front();
                pending.pop_front();
                if (value >= '0' && value <= '7') {
                    const unsigned pins = value - '0';
                    const bool rising = !dut.jtag_tck && (pins & 4);
                    dut.jtag_tck = (pins >> 2) & 1;
                    dut.jtag_tms = (pins >> 1) & 1;
                    dut.jtag_tdi = pins & 1;
                    dut.eval();
                    if (rising) tap.clock(dut.jtag_tms, dut.jtag_tdi, cycle, std::cout);
                } else if (value == 'R') {
                    dut.eval();
                    ++tdoSamples;
                    tdoEnabledSamples += dut.jtag_tdoEnable;
                    sendByte(client, dut.jtag_tdo ? '1' : '0');
                } else if (value >= 'r' && value <= 'u') {
                    const unsigned resets = value - 'r';
                    dut.reset = resets & 1;
                    dut.jtag_trstN = !(resets & 2);
                    if (!dut.jtag_trstN) tap.resetNow();
                    dut.eval();
                } else if (value == 'Q') {
                    finished = true;
                } else if (value != 'B' && value != 'b') {
                    throw std::runtime_error("Unknown remote bitbang command");
                }
            }
            if (finished) break;

            dut.clock = 0;
            dut.timeValue = cycle;
            dut.instruction_request_ready = !dut.reset && !instruction.active && (!delay || random() % 3 == 0);
            dut.data_request_ready = !dut.reset && !data.active && (!delay || random() % 3 == 0);
            dut.instruction_response_valid = instruction.active && cycle >= instruction.due;
            dut.data_response_valid = data.active && cycle >= data.due;
            dut.instruction_response_bits_data = instruction.data;
            dut.data_response_bits_data = data.data;
            dut.instruction_response_bits_fault = 0;
            dut.data_response_bits_fault = 0;
            dut.eval();
            if (dut.systemReset && (instruction.active || data.active))
                throw std::runtime_error("Debug reset crossed an accepted native transfer");
            if (bool(dut.reset) != previousExternal) {
                externalResets += dut.reset;
                std::cout << "Z " << cycle << ' ' << unsigned(dut.reset) << ' ' << unsigned(dut.systemReset) << '\n';
                previousExternal = dut.reset;
            }
            if (bool(dut.systemReset) != previousDebug) {
                debugResets += dut.systemReset;
                std::cout << "Z " << cycle << ' ' << unsigned(dut.reset) << ' ' << unsigned(dut.systemReset) << '\n';
                previousDebug = dut.systemReset;
            }
            if ((dut.instruction_request_valid && dut.instruction_request_bits_operation) ||
                (dut.data_request_valid && dut.data_request_bits_operation))
                throw std::runtime_error("Unexpected atomic memory request");
            auto observe = [&](Port &port, char name, bool valid, bool ready, Request request,
                               bool responseValid, bool responseReady) {
                if (!dut.reset && !dut.systemReset && port.held && (!valid || !(request == port.previous)))
                    throw std::runtime_error("Native request changed under backpressure");
                if (responseValid && responseReady) {
                    if (!port.active) throw std::runtime_error("Unowned native response");
                    if (port.request.write) {
                        auto &value = memory[port.request.address & ~3u];
                        for (unsigned lane = 0; lane < 4; ++lane)
                            if (port.request.mask & (1u << lane))
                                value = (value & ~(255u << (8 * lane))) |
                                        (port.request.data & (255u << (8 * lane)));
                    }
                    std::cout << "S " << cycle << ' ' << name << ' ' << port.request.address << ' '
                              << port.request.write << ' ' << port.request.data << ' ' << port.request.mask << ' '
                              << port.request.size << ' ' << port.data << " 0\n";
                    port.active = false;
                }
                port.held = valid && !ready && !dut.reset && !dut.systemReset;
                port.previous = request;
                if (valid && ready) {
                    if (port.active) throw std::runtime_error("Multiple outstanding native requests");
                    if (request.size > 2 || request.address % (1u << request.size) ||
                        (name == 'I' && (request.write || request.size != 2)) ||
                        request.mask != (request.write ? ((1u << (1u << request.size)) - 1) << (request.address % 4) : 0u))
                        throw std::runtime_error("Invalid native memory request");
                    port.active = true;
                    port.request = request;
                    port.data = memory[request.address & ~3u];
                    port.due = cycle + 1 + (delay ? random() % delay : 0);
                }
            };
            observe(instruction, 'I', dut.instruction_request_valid, dut.instruction_request_ready,
                    {dut.instruction_request_bits_address, dut.instruction_request_bits_data,
                     dut.instruction_request_bits_mask, dut.instruction_request_bits_size,
                     bool(dut.instruction_request_bits_write), bool(dut.instruction_request_bits_machine)},
                    dut.instruction_response_valid, dut.instruction_response_ready);
            observe(data, 'D', dut.data_request_valid, dut.data_request_ready,
                    {dut.data_request_bits_address, dut.data_request_bits_data,
                     dut.data_request_bits_mask, dut.data_request_bits_size,
                     bool(dut.data_request_bits_write), bool(dut.data_request_bits_machine)},
                    dut.data_response_valid, dut.data_response_ready);
            if (dut.retire_valid) {
                if (dut.interrupt_valid) throw std::runtime_error("Unexpected interrupt during host acceptance");
                std::cout << "R " << cycle << ' ' << dut.retire_pc << ' ' << dut.retire_word << ' '
                          << dut.retire_nextPc << ' ' << unsigned(dut.retire_rd) << ' ' << unsigned(dut.retire_writes)
                          << ' ' << dut.retire_value << ' ' << unsigned(dut.retire_trap) << ' ' << dut.retire_cause
                          << ' ' << dut.retire_tval << ' ' << unsigned(dut.retire_userMode) << '\n';
            }
            dut.clock = 1;
            dut.eval();
        }
        if (!finished) throw std::runtime_error("Host simulation exceeded its cycle limit");
        std::cout << "F " << cycle << ' ' << externalResets << ' ' << debugResets << '\n';
        std::cout << "E " << tdoSamples << ' ' << tdoEnabledSamples << '\n';
        for (const auto &[location, value] : memory) std::cout << "W " << location << ' ' << value << '\n';
        dut.final();
        close(client);
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        if (client >= 0) close(client);
        if (listener >= 0) close(listener);
        return 1;
    }
}
