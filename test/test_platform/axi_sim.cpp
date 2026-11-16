// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VDitDahE2AxiLite.h"
#include "verilated.h"
#include <array>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

struct Request {
    uint32_t owner, write, address, data, mask, size, machine, operation;
    uint32_t awDelay, wDelay, arDelay, responseDelay, nativeDelay, response;
};
struct Address { uint32_t owner, address; };
struct WriteData { uint32_t data, mask; };
struct Reply { uint32_t readyCycle, owner, data, response; };

int main(int argc, char **argv) {
    Verilated::commandArgs(argc, argv);
    if (argc != 3) return 2;
    std::ifstream vectors(argv[1]), initial(argv[2]);
    std::array<std::vector<Request>, 2> queues;
    Request row;
    while (vectors >> row.owner >> row.write >> row.address >> row.data >> row.mask >> row.size >> row.machine >> row.operation
                   >> row.awDelay >> row.wDelay >> row.arDelay >> row.responseDelay
                   >> row.nativeDelay >> row.response) {
        if (row.owner > 1) throw std::runtime_error("Invalid owner");
        queues[row.owner].push_back(row);
    }
    std::array<uint32_t, 256> memory{};
    for (auto &word : memory) if (!(initial >> word)) throw std::runtime_error("Incomplete memory");
    VDitDahE2AxiLite dut;
    std::array<size_t, 2> next{};
    std::array<bool, 2> active{};
    std::array<uint32_t, 2> started{}, nativeSeen{};
    std::array<Request, 2> current{};
    std::deque<Address> addresses;
    std::deque<WriteData> writes;
    std::deque<Reply> readReplies, writeReplies;
    unsigned idle = 0;
    auto drive = [&](unsigned owner, const Request &request, bool valid) {
        if (owner) {
            dut.data_request_valid = valid;
            dut.data_request_bits_address = request.address;
            dut.data_request_bits_write = request.write;
            dut.data_request_bits_data = request.data;
            dut.data_request_bits_mask = request.mask;
            dut.data_request_bits_size = request.size;
            dut.data_request_bits_machine = request.machine;
            dut.data_request_bits_operation = request.operation;
        } else {
            dut.instruction_request_valid = valid;
            dut.instruction_request_bits_address = request.address;
            dut.instruction_request_bits_write = request.write;
            dut.instruction_request_bits_data = request.data;
            dut.instruction_request_bits_mask = request.mask;
            dut.instruction_request_bits_size = request.size;
            dut.instruction_request_bits_machine = request.machine;
            dut.instruction_request_bits_operation = request.operation;
        }
    };
    std::cout << "cycle reset iv ir ia iw id im iz ip ix ov or od of dv dr da dw dd dm dz dp dx pv pr pd pf "
                 "av ay aa ap wv wy wd wm bv by br rv ry ra rp qv qy qd qr\n";
    for (uint32_t cycle = 0; cycle < 1000000; ++cycle) {
        dut.clock = 0;
        dut.reset = cycle < 2;
        for (unsigned owner = 0; owner < 2; ++owner) {
            bool valid = cycle >= 2 && !active[owner] && next[owner] < queues[owner].size();
            drive(owner, valid ? queues[owner][next[owner]] : Request{}, valid);
        }
        dut.instruction_response_ready = !active[0] || !current[0].nativeDelay ||
            (nativeSeen[0] && cycle - nativeSeen[0] >= current[0].nativeDelay);
        dut.data_response_ready = !active[1] || !current[1].nativeDelay ||
            (nativeSeen[1] && cycle - nativeSeen[1] >= current[1].nativeDelay);
        dut.axi_aw_ready = dut.axi_w_ready = dut.axi_ar_ready = 0;
        dut.axi_b_valid = !writeReplies.empty() && cycle >= writeReplies.front().readyCycle;
        dut.axi_b_bits_response = writeReplies.empty() ? 0 : writeReplies.front().response;
        dut.axi_r_valid = !readReplies.empty() && cycle >= readReplies.front().readyCycle;
        dut.axi_r_bits_response = readReplies.empty() ? 0 : readReplies.front().response;
        dut.axi_r_bits_data = readReplies.empty() ? 0 : readReplies.front().data;
        dut.eval();
        const unsigned awOwner = !(dut.axi_aw_bits_protection & 4);
        const unsigned arOwner = !(dut.axi_ar_bits_protection & 4);
        dut.axi_aw_ready = active[awOwner] && cycle - started[awOwner] > current[awOwner].awDelay;
        unsigned writeOwner = !addresses.empty() ? addresses.front().owner : awOwner;
        dut.axi_w_ready = active[writeOwner] && cycle - started[writeOwner] > current[writeOwner].wDelay;
        dut.axi_ar_ready = readReplies.size() < 2 && active[arOwner] &&
            cycle - started[arOwner] > current[arOwner].arDelay;
        dut.eval();
        for (unsigned owner = 0; owner < 2; ++owner) {
            const bool completed = owner ? dut.data_response_valid && dut.data_response_ready :
                                           dut.instruction_response_valid && dut.instruction_response_ready;
            if (active[owner] && completed && next[owner] < queues[owner].size())
                drive(owner, queues[owner][next[owner]], true);
        }
        dut.eval();
#define P(signal) std::cout << ' ' << uint64_t(dut.signal)
        std::cout << cycle;
        P(reset);
        P(instruction_request_valid); P(instruction_request_ready); P(instruction_request_bits_address);
        P(instruction_request_bits_write); P(instruction_request_bits_data);
        P(instruction_request_bits_mask); P(instruction_request_bits_size); P(instruction_request_bits_machine); P(instruction_request_bits_operation);
        P(instruction_response_valid); P(instruction_response_ready);
        P(instruction_response_bits_data); P(instruction_response_bits_fault);
        P(data_request_valid); P(data_request_ready); P(data_request_bits_address); P(data_request_bits_write);
        P(data_request_bits_data); P(data_request_bits_mask); P(data_request_bits_size); P(data_request_bits_machine); P(data_request_bits_operation);
        P(data_response_valid); P(data_response_ready); P(data_response_bits_data); P(data_response_bits_fault);
        P(axi_aw_valid); P(axi_aw_ready); P(axi_aw_bits_address); P(axi_aw_bits_protection);
        P(axi_w_valid); P(axi_w_ready); P(axi_w_bits_data); P(axi_w_bits_strobe);
        P(axi_b_valid); P(axi_b_ready); P(axi_b_bits_response);
        P(axi_ar_valid); P(axi_ar_ready); P(axi_ar_bits_address); P(axi_ar_bits_protection);
        P(axi_r_valid); P(axi_r_ready); P(axi_r_bits_data); P(axi_r_bits_response);
        std::cout << '\n';
#undef P
        if (!dut.reset) {
            if (dut.axi_aw_valid && dut.axi_aw_ready)
                addresses.push_back({awOwner, dut.axi_aw_bits_address});
            if (dut.axi_w_valid && dut.axi_w_ready)
                writes.push_back({dut.axi_w_bits_data, dut.axi_w_bits_strobe});
            while (!addresses.empty() && !writes.empty()) {
                const auto address = addresses.front(); addresses.pop_front();
                const auto data = writes.front(); writes.pop_front();
                const Request &request = current[address.owner];
                if (request.response == 0) {
                    auto &word = memory[(address.address >> 2) & 255];
                    for (unsigned lane = 0; lane < 4; ++lane) if (data.mask & (1u << lane)) {
                        const uint32_t mask = 255u << (8 * lane);
                        word = (word & ~mask) | (data.data & mask);
                    }
                }
                writeReplies.push_back({cycle + request.responseDelay + 1, address.owner, 0, request.response});
            }
            if (dut.axi_ar_valid && dut.axi_ar_ready) {
                const Request &request = current[arOwner];
                readReplies.push_back({cycle + request.responseDelay + 1, arOwner,
                                       memory[(dut.axi_ar_bits_address >> 2) & 255], request.response});
            }
            if (dut.axi_b_valid && dut.axi_b_ready) writeReplies.pop_front();
            if (dut.axi_r_valid && dut.axi_r_ready) readReplies.pop_front();
            for (unsigned owner = 0; owner < 2; ++owner) {
                const bool visible = owner ? dut.data_response_valid : dut.instruction_response_valid;
                const bool completed = owner ? dut.data_response_valid && dut.data_response_ready :
                                               dut.instruction_response_valid && dut.instruction_response_ready;
                if (visible && !nativeSeen[owner]) nativeSeen[owner] = cycle;
                if (completed) active[owner] = false;
            }
            const std::array<bool, 2> accepted{dut.instruction_request_valid && dut.instruction_request_ready,
                                              dut.data_request_valid && dut.data_request_ready};
            for (unsigned owner = 0; owner < 2; ++owner) if (accepted[owner]) {
                current[owner] = queues[owner][next[owner]++];
                active[owner] = true;
                started[owner] = cycle;
                nativeSeen[owner] = 0;
            }
        }
        dut.clock = 1;
        dut.eval();
        if (!active[0] && !active[1] && next[0] == queues[0].size() && next[1] == queues[1].size() &&
            readReplies.empty() && writeReplies.empty() && addresses.empty() && writes.empty()) {
            if (++idle == 8) return 0;
        } else idle = 0;
    }
    std::cerr << "AXI simulation exceeded cycle limit\n";
    return 1;
}
