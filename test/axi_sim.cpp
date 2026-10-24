// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VDitDahE2AxiLite.h"
#include "verilated.h"
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

struct Request {
    uint32_t owner, write, address, data, mask, size;
    uint32_t awDelay, wDelay, arDelay, responseDelay, nativeDelay, response;
};

int main(int argc, char **argv) {
    Verilated::commandArgs(argc, argv);
    if (argc != 3) return 2;
    std::ifstream vectors(argv[1]), initial(argv[2]);
    std::array<std::vector<Request>, 2> queues;
    Request row;
    while (vectors >> row.owner >> row.write >> row.address >> row.data >> row.mask >> row.size
                   >> row.awDelay >> row.wDelay >> row.arDelay >> row.responseDelay
                   >> row.nativeDelay >> row.response) {
        if (row.owner > 1) throw std::runtime_error("Invalid owner");
        queues[row.owner].push_back(row);
    }
    std::array<uint32_t, 256> memory{};
    for (auto &word : memory) {
        if (!(initial >> word)) throw std::runtime_error("Incomplete memory");
    }
    VDitDahE2AxiLite dut;
    std::array<size_t, 2> next{};
    bool active = false, aw = false, w = false, ar = false, responseDone = false;
    uint32_t started = 0, busDone = 0, nativeSeen = 0, readData = 0;
    uint32_t busAddress = 0, busData = 0, busMask = 0;
    Request current{};
    unsigned idle = 0;
    std::cout << "cycle reset iv ir ia iw id im iz ov or od of dv dr da dw dd dm dz pv pr pd pf "
                 "av ay aa ap wv wy wd wm bv by br rv ry ra rp qv qy qd qr\n";
    for (uint32_t cycle = 0; cycle < 1000000; ++cycle) {
        dut.clock = 0;
        dut.reset = cycle < 2;
        const bool offerI = cycle >= 2 && (!active || current.owner != 0) && next[0] < queues[0].size();
        const bool offerD = cycle >= 2 && (!active || current.owner != 1) && next[1] < queues[1].size();
        const Request i = offerI ? queues[0][next[0]] : Request{};
        const Request d = offerD ? queues[1][next[1]] : Request{};
        dut.instruction_request_valid = offerI;
        dut.instruction_request_bits_address = i.address;
        dut.instruction_request_bits_write = i.write;
        dut.instruction_request_bits_data = i.data;
        dut.instruction_request_bits_mask = i.mask;
        dut.instruction_request_bits_size = i.size;
        dut.data_request_valid = offerD;
        dut.data_request_bits_address = d.address;
        dut.data_request_bits_write = d.write;
        dut.data_request_bits_data = d.data;
        dut.data_request_bits_mask = d.mask;
        dut.data_request_bits_size = d.size;
        dut.instruction_response_ready = !active || current.owner != 0 ||
            (nativeSeen && cycle - nativeSeen >= current.nativeDelay);
        dut.data_response_ready = !active || current.owner != 1 ||
            (nativeSeen && cycle - nativeSeen >= current.nativeDelay);
        dut.axi_aw_ready = active && cycle - started > current.awDelay;
        dut.axi_w_ready = active && cycle - started > current.wDelay;
        dut.axi_ar_ready = active && cycle - started > current.arDelay;
        const bool reply = active && busDone && !responseDone && cycle - busDone > current.responseDelay;
        dut.axi_b_valid = reply && current.write;
        dut.axi_b_bits_response = active ? current.response : 0;
        dut.axi_r_valid = reply && !current.write;
        dut.axi_r_bits_response = active ? current.response : 0;
        dut.axi_r_bits_data = readData;
        dut.eval();
#define P(signal) std::cout << ' ' << uint64_t(dut.signal)
        std::cout << cycle;
        P(reset);
        P(instruction_request_valid); P(instruction_request_ready); P(instruction_request_bits_address);
        P(instruction_request_bits_write); P(instruction_request_bits_data);
        P(instruction_request_bits_mask); P(instruction_request_bits_size);
        P(instruction_response_valid); P(instruction_response_ready);
        P(instruction_response_bits_data); P(instruction_response_bits_fault);
        P(data_request_valid); P(data_request_ready); P(data_request_bits_address); P(data_request_bits_write);
        P(data_request_bits_data); P(data_request_bits_mask); P(data_request_bits_size);
        P(data_response_valid); P(data_response_ready); P(data_response_bits_data); P(data_response_bits_fault);
        P(axi_aw_valid); P(axi_aw_ready); P(axi_aw_bits_address); P(axi_aw_bits_protection);
        P(axi_w_valid); P(axi_w_ready); P(axi_w_bits_data); P(axi_w_bits_strobe);
        P(axi_b_valid); P(axi_b_ready); P(axi_b_bits_response);
        P(axi_ar_valid); P(axi_ar_ready); P(axi_ar_bits_address); P(axi_ar_bits_protection);
        P(axi_r_valid); P(axi_r_ready); P(axi_r_bits_data); P(axi_r_bits_response);
        std::cout << '\n';
#undef P
        if (!dut.reset) {
            if (dut.axi_aw_valid && dut.axi_aw_ready) {
                aw = true;
                busAddress = dut.axi_aw_bits_address;
            }
            if (dut.axi_w_valid && dut.axi_w_ready) {
                w = true;
                busData = dut.axi_w_bits_data;
                busMask = dut.axi_w_bits_strobe;
            }
            if (dut.axi_ar_valid && dut.axi_ar_ready) {
                ar = true;
                busAddress = dut.axi_ar_bits_address;
                readData = memory[(busAddress >> 2) & 255];
            }
            if (!busDone && active && (current.write ? aw && w : ar)) {
                busDone = cycle;
                if (current.write && current.response == 0) {
                    auto &word = memory[(busAddress >> 2) & 255];
                    for (unsigned lane = 0; lane < 4; ++lane) {
                        if (busMask & (1u << lane)) {
                            const uint32_t mask = 255u << (8 * lane);
                            word = (word & ~mask) | (busData & mask);
                        }
                    }
                }
            }
            if ((dut.axi_b_valid && dut.axi_b_ready) || (dut.axi_r_valid && dut.axi_r_ready))
                responseDone = true;
            if ((dut.instruction_response_valid || dut.data_response_valid) && !nativeSeen)
                nativeSeen = cycle;
            if ((dut.instruction_response_valid && dut.instruction_response_ready) ||
                (dut.data_response_valid && dut.data_response_ready)) active = false;
            if ((dut.instruction_request_valid && dut.instruction_request_ready) ||
                (dut.data_request_valid && dut.data_request_ready)) {
                const unsigned owner = dut.data_request_valid && dut.data_request_ready;
                current = queues[owner][next[owner]++];
                active = true;
                started = cycle;
                aw = w = ar = responseDone = false;
                busDone = nativeSeen = 0;
            }
        }
        dut.clock = 1;
        dut.eval();
        if (!active && next[0] == queues[0].size() && next[1] == queues[1].size()) {
            if (++idle == 8) return 0;
        } else idle = 0;
    }
    std::cerr << "AXI simulation exceeded cycle limit\n";
    return 1;
}
