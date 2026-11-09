// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VDitDahE2.h"
#include "verilated.h"
#include <cstdint>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using Sample = std::map<std::string, uint64_t>;

std::string json(const Sample &sample) {
    std::ostringstream out;
    out << '{';
    const char *separator = "";
    for (const auto &[key, value] : sample) {
        out << separator << '"' << key << "\":" << value;
        separator = ",";
    }
    out << '}';
    return out.str();
}

std::string json(const std::vector<Sample> &samples) {
    std::string result = "[", separator;
    for (const auto &sample : samples) {
        result += separator + json(sample);
        separator = ",";
    }
    return result + ']';
}

struct Harness {
    VerilatedContext context;
    VDitDahE2 dut{&context};
    std::map<uint32_t, uint32_t> words;
    std::vector<Sample> retired;
    uint32_t faultAddress = UINT32_MAX;
    uint32_t responseData = 0;
    bool active = false, responseFault = false;
    uint64_t cycle = 0, dataOffers = 0, faultResponses = 0;

    explicit Harness(std::map<uint32_t, uint32_t> program) : words(std::move(program)) {
        dut.clock = 0;
        dut.reset = 1;
        dut.interrupts_software = dut.interrupts_timer = dut.interrupts_external = 0;
        dut.timeValue = 0;
        dut.instruction_request_ready = dut.data_request_ready = 0;
        dut.instruction_response_valid = dut.data_response_valid = 0;
        dut.instruction_response_bits_data = dut.data_response_bits_data = 0;
        dut.instruction_response_bits_fault = dut.data_response_bits_fault = 0;
        for (unsigned edge = 0; edge != 4; ++edge) {
            dut.clock = edge & 1;
            dut.eval();
        }
        dut.reset = 0;
    }

    Sample retirement() const {
        return {{"pc", dut.retire_pc}, {"raw", dut.retire_word}, {"insn", dut.retire_insn},
                {"order", dut.retire_order}, {"length", dut.retire_length},
                {"trap", dut.retire_trap}, {"cause", dut.retire_cause}, {"tval", dut.retire_tval},
                {"rd", dut.retire_rd}, {"writes", dut.retire_writes}, {"value", dut.retire_value},
                {"rs1", dut.retire_rs1}, {"rs1_data", dut.retire_rs1Data},
                {"rs2", dut.retire_rs2}, {"rs2_data", dut.retire_rs2Data},
                {"memory_address", dut.retire_memoryAddress}, {"read_mask", dut.retire_memoryReadMask},
                {"write_mask", dut.retire_memoryWriteMask}, {"read_data", dut.retire_memoryReadData},
                {"write_data", dut.retire_memoryWriteData}, {"operation", dut.retire_memoryOperation},
                {"operand", dut.retire_memoryOperand}, {"response", dut.retire_memoryResponse},
                {"fault", dut.retire_memoryFault}, {"fault_read_mask", dut.retire_faultReadMask},
                {"fault_write_mask", dut.retire_faultWriteMask}, {"csr_valid", dut.retire_csr_valid},
                {"csr_read_mask", dut.retire_csr_readMask}, {"csr_write_mask", dut.retire_csr_writeMask},
                {"status_before", dut.retire_csrMstatus_before},
                {"status_after", dut.retire_csrMstatus_after},
                {"status_mask", dut.retire_csrMstatus_writeMask}};
    }

    Sample interrupt() const {
        return {{"valid", dut.interrupt_valid}, {"retire_valid", dut.retire_valid},
                {"sleeping", dut.sleeping}, {"pc", dut.interrupt_pc},
                {"target", dut.interrupt_target}, {"cause", dut.interrupt_cause},
                {"status_before", dut.interrupt_csrMstatus_before},
                {"status_after", dut.interrupt_csrMstatus_after},
                {"epc_before", dut.interrupt_csrMepc_before},
                {"epc_after", dut.interrupt_csrMepc_after},
                {"cause_before", dut.interrupt_csrMcause_before},
                {"cause_after", dut.interrupt_csrMcause_after},
                {"value_before", dut.interrupt_csrMtval_before},
                {"value_after", dut.interrupt_csrMtval_after}};
    }

    void drive() {
        dut.instruction_request_ready = !active;
        dut.instruction_response_valid = active;
        dut.instruction_response_bits_data = responseData;
        dut.instruction_response_bits_fault = responseFault;
        dut.data_request_ready = 1;
        dut.data_response_valid = 0;
        dut.timeValue = cycle;
    }

    void tick() {
        dut.clock = 0;
        drive();
        dut.eval();
        dataOffers += dut.data_request_valid;
        if (dut.retire_valid) retired.push_back(retirement());
        if (dut.instruction_response_valid && dut.instruction_response_ready) {
            if (!active) throw std::runtime_error("Unowned instruction response");
            faultResponses += responseFault;
            active = false;
        }
        if (dut.instruction_request_valid && dut.instruction_request_ready) {
            if (active) throw std::runtime_error("Overlapping instruction requests");
            const uint32_t address = dut.instruction_request_bits_address;
            if (dut.instruction_request_bits_write || dut.instruction_request_bits_size != 2 || address % 4)
                throw std::runtime_error("Invalid instruction request");
            responseData = words.count(address) ? words.at(address) : 0x00000013;
            responseFault = address == faultAddress;
            active = true;
        }
        dut.clock = 1;
        dut.eval();
        ++cycle;
    }

    void runTo(uint32_t pc) {
        while (cycle != 300) {
            const auto count = retired.size();
            tick();
            if (retired.size() != count && retired.back().at("pc") == pc) return;
        }
        throw std::runtime_error("Retirement edge was not reached within 300 cycles");
    }
};

std::string fetchFault() {
    Harness run({{0, 0x10000093}, {4, 0x05500113}, {8, 0x0020a1af}});
    run.faultAddress = 8;
    run.runTo(8);
    return "{\"schema\":\"ditdah-e2.retirement-edges.v1\",\"case\":\"fetch-fault-atomic\","
           "\"retired\":" + json(run.retired) + ",\"data_offers\":" + std::to_string(run.dataOffers) +
           ",\"fault_responses\":" + std::to_string(run.faultResponses) + "}";
}

std::string resetScenario(bool reset) {
    Harness run({{0, 0x08000093}, {4, 0x30409073}, {8, 0x00800093},
                 {12, 0x30009073}, {16, 0x10500073}});
    run.runTo(16);
    run.dut.clock = 0;
    run.drive();
    run.dut.interrupts_timer = 1;
    run.dut.eval();
    const auto eligible = run.interrupt();
    run.dut.reset = reset;
    run.dut.eval();
    const auto observed = run.interrupt();
    run.dut.clock = 1;
    run.dut.eval();
    run.dut.clock = 0;
    run.dut.reset = 0;
    run.dut.eval();
    const auto stored = run.interrupt();
    return "{\"retired\":" + json(run.retired) + ",\"eligible\":" + json(eligible) +
           ",\"observed\":" + json(observed) + ",\"stored\":" + json(stored) +
           ",\"data_offers\":" + std::to_string(run.dataOffers) + "}";
}

int main(int argc, char **argv) {
    try {
        if (argc != 2) throw std::runtime_error("Expected one retirement edge case");
        const std::string name = argv[1];
        if (name == "fetch-fault-atomic") std::cout << fetchFault() << '\n';
        else if (name == "reset-irq")
            std::cout << "{\"schema\":\"ditdah-e2.retirement-edges.v1\",\"case\":\"reset-irq\","
                         "\"positive\":" << resetScenario(false) << ",\"reset\":" << resetScenario(true) << "}\n";
        else throw std::runtime_error("Unknown retirement edge case");
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
