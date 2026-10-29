// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <ostream>

template<class Dut>
void writeRvfi(std::ostream &out, const Dut &dut, uint64_t cycle) {
    if (!dut.retire_valid) return;
    const auto format = out.flags();
    out.setf(std::ios_base::dec, std::ios_base::basefield);
    out.unsetf(std::ios_base::showbase | std::ios_base::showpos);
    out << "{\"schema\":\"ditdah-e2.rvfi.v1\"";
    const auto number = [&](const char *name, uint64_t value) {
        out << ",\"" << name << "\":" << value;
    };
    const auto flag = [&](const char *name, bool value) {
        out << ",\"" << name << "\":" << (value ? "true" : "false");
    };
    number("cycle", cycle);
    number("order", dut.retire_order);
    number("insn", dut.retire_insn);
    flag("trap", dut.retire_trap);
    flag("halt", false);
    flag("intr", dut.retire_intr);
    number("mode", dut.retire_userMode ? 0 : 3);
    number("ixl", 1);
    number("rs1_addr", dut.retire_rs1);
    number("rs2_addr", dut.retire_rs2);
    number("rs1_rdata", dut.retire_rs1Data);
    number("rs2_rdata", dut.retire_rs2Data);
    number("rd_addr", dut.retire_rd);
    number("rd_wdata", dut.retire_value);
    number("pc_rdata", dut.retire_pc);
    number("pc_wdata", dut.retire_nextPc);
    number("mem_addr", dut.retire_memoryAddress);
    number("mem_rmask", dut.retire_memoryReadMask);
    number("mem_wmask", dut.retire_memoryWriteMask);
    number("mem_rdata", dut.retire_memoryReadData);
    number("mem_wdata", dut.retire_memoryWriteData);
    flag("mem_fault", dut.retire_memoryFault);
    number("mem_fault_rmask", dut.retire_faultReadMask);
    number("mem_fault_wmask", dut.retire_faultWriteMask);
    number("length", dut.retire_length);
    number("cause", dut.retire_cause);
    number("tval", dut.retire_tval);
    number("misa", dut.retire_misa);
    number("memory_operation", dut.retire_memoryOperation);
    number("memory_operand", dut.retire_memoryOperand);
    number("memory_response", dut.retire_memoryResponse);
    out << ",\"csr\":{\"valid\":" << (dut.retire_csr_valid ? "true" : "false");
    number("address", dut.retire_csr_address);
    number("rmask", dut.retire_csr_readMask);
    number("wmask", dut.retire_csr_writeMask);
    number("rdata", dut.retire_csr_readData);
    number("wdata", dut.retire_csr_writeData);
    out << "},\"csr_states\":{";
    bool first = true;
    const auto state = [&](const char *name, uint64_t before, uint64_t after, uint64_t mask) {
        if (!first) out << ',';
        first = false;
        out << '"' << name << "\":{\"before\":" << before
            << ",\"after\":" << after << ",\"wmask\":" << mask << '}';
    };
    state("mstatus", dut.retire_csrMstatus_before, dut.retire_csrMstatus_after,
          dut.retire_csrMstatus_writeMask);
    state("mepc", dut.retire_csrMepc_before, dut.retire_csrMepc_after,
          dut.retire_csrMepc_writeMask);
    state("mcause", dut.retire_csrMcause_before, dut.retire_csrMcause_after,
          dut.retire_csrMcause_writeMask);
    state("mtval", dut.retire_csrMtval_before, dut.retire_csrMtval_after,
          dut.retire_csrMtval_writeMask);
    state("mcycle", dut.retire_csrCycle_before, dut.retire_csrCycle_after,
          dut.retire_csrCycle_writeMask);
    state("minstret", dut.retire_csrInstret_before, dut.retire_csrInstret_after,
          dut.retire_csrInstret_writeMask);
    out << '}';
    number("time", dut.retire_csrTime);
    out << "}\n";
    out.flags(format);
    if (!out) throw std::ios_base::failure("Retirement trace write failed");
}

template<class Dut>
void writeRvfiInterrupt(std::ostream &out, const Dut &dut, uint64_t cycle) {
    if (!dut.interrupt_valid) return;
    const auto format = out.flags();
    out.setf(std::ios_base::dec, std::ios_base::basefield);
    out.unsetf(std::ios_base::showbase | std::ios_base::showpos);
    out << "{\"schema\":\"ditdah-e2.irq.v1\"";
    const auto number = [&](const char *name, uint64_t value) {
        out << ",\"" << name << "\":" << value;
    };
    number("cycle", cycle);
    number("pc", dut.interrupt_pc);
    number("target", dut.interrupt_target);
    number("cause", dut.interrupt_cause);
    number("mode", dut.interrupt_userMode ? 0 : 3);
    out << ",\"csr_states\":{";
    bool first = true;
    const auto state = [&](const char *name, uint64_t before, uint64_t after, uint64_t mask) {
        if (!first) out << ',';
        first = false;
        out << '"' << name << "\":{\"before\":" << before
            << ",\"after\":" << after << ",\"wmask\":" << mask << '}';
    };
    state("mstatus", dut.interrupt_csrMstatus_before, dut.interrupt_csrMstatus_after,
          dut.interrupt_csrMstatus_writeMask);
    state("mepc", dut.interrupt_csrMepc_before, dut.interrupt_csrMepc_after,
          dut.interrupt_csrMepc_writeMask);
    state("mcause", dut.interrupt_csrMcause_before, dut.interrupt_csrMcause_after,
          dut.interrupt_csrMcause_writeMask);
    state("mtval", dut.interrupt_csrMtval_before, dut.interrupt_csrMtval_after,
          dut.interrupt_csrMtval_writeMask);
    out << "}}\n";
    out.flags(format);
    if (!out) throw std::ios_base::failure("Interrupt trace write failed");
}
