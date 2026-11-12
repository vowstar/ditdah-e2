// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module debug_program_core_formal(input clock, input reset);
  wire instruction_request_valid, instruction_request_ready;
  wire [31:0] instruction_request_bits_address, instruction_request_bits_data;
  wire instruction_request_bits_write, instruction_request_bits_machine;
  wire [3:0] instruction_request_bits_mask, instruction_request_bits_operation;
  wire [1:0] instruction_request_bits_size;
  wire instruction_response_valid, instruction_response_ready, instruction_response_bits_fault;
  wire [31:0] instruction_response_bits_data;
  wire data_request_valid, data_request_ready, data_request_bits_write, data_request_bits_machine;
  wire [31:0] data_request_bits_address, data_request_bits_data;
  wire [3:0] data_request_bits_mask, data_request_bits_operation;
  wire [1:0] data_request_bits_size;
  wire data_response_valid, data_response_ready, data_response_bits_fault;
  wire [31:0] data_response_bits_data;
  wire retire_valid, retire_writes, retire_trap, retire_userMode;
  wire [31:0] retire_pc, retire_word, retire_nextPc, retire_value, retire_cause, retire_tval;
  wire [4:0] retire_rd;
  wire loadUse, forward, redirect, memoryWait, sleeping;
  wire interrupts_software = 0, interrupts_timer = 0, interrupts_external = 0;
  wire [63:0] timeValue = 0;
  wire interrupt_valid;
  wire [31:0] interrupt_pc, interrupt_target, interrupt_cause;
  wire mulDiv_start, mulDiv_resultValid, mulDiv_finish, mulDiv_cancel;
  wire [31:0] mulDiv_pc, mulDiv_value;
  wire dmi_request_ready, dmi_response_valid;
  wire [31:0] dmi_response_bits_data;
  wire [1:0] dmi_response_bits_status;
  reg dmi_request_valid = 0, dmi_response_ready = 1;
  reg [6:0] dmi_request_bits_address;
  reg [31:0] dmi_request_bits_data;
  reg [1:0] dmi_request_bits_op;
  wire systemReset;
  wire debugExecution_valid, debugExecution_writes, debugExecution_fault;
  wire debugExecution_ebreak, debugExecution_csr, debugExecution_load, debugExecution_store;
  wire [2:0] debugExecution_sequence, debugExecution_length;
  wire [31:0] debugExecution_pc, debugExecution_word, debugExecution_value, debugExecution_address;
  wire [4:0] debugExecution_rd;

  DitDahE2 dut (
    .retire_order(), .retire_length(), .retire_insn(),
    .retire_intr(), .retire_rs1(), .retire_rs1Data(),
    .retire_rs2(), .retire_rs2Data(), .retire_memoryReadMask(),
    .retire_memoryReadData(), .retire_memoryOperation(), .retire_memoryResponse(),
    .retire_memoryFault(), .retire_faultReadMask(), .retire_misa(),
    .retire_csr_valid(), .retire_csr_address(), .retire_csr_readMask(),
    .retire_csrCycle_before(), .interrupt_csrMstatus_before(),
    .retire_memoryAddress(), .retire_memoryWriteMask(), .retire_memoryWriteData(),
    .retire_memoryOperand(), .retire_faultWriteMask(), .retire_csr_writeMask(),
    .retire_csr_readData(), .retire_csr_writeData(), .retire_csrMstatus_before(),
    .retire_csrMstatus_after(), .retire_csrMstatus_writeMask(), .retire_csrMepc_before(),
    .retire_csrMepc_after(), .retire_csrMepc_writeMask(), .retire_csrMcause_before(),
    .retire_csrMcause_after(), .retire_csrMcause_writeMask(), .retire_csrMtval_before(),
    .retire_csrMtval_after(), .retire_csrMtval_writeMask(), .retire_csrCycle_after(),
    .retire_csrCycle_writeMask(), .retire_csrInstret_before(), .retire_csrInstret_after(),
    .retire_csrInstret_writeMask(), .retire_csrTime(), .interrupt_userMode(),
    .interrupt_csrMstatus_after(), .interrupt_csrMstatus_writeMask(), .interrupt_csrMepc_before(),
    .interrupt_csrMepc_after(), .interrupt_csrMepc_writeMask(), .interrupt_csrMcause_before(),
    .interrupt_csrMcause_after(), .interrupt_csrMcause_writeMask(), .interrupt_csrMtval_before(),
    .interrupt_csrMtval_after(), .interrupt_csrMtval_writeMask(),
    .*
  );

  reg initialized = 0;
  always @($global_clock) begin
    if (!reset) initialized <= 1;
    if (!initialized) initial_common_cold_reset: assume(reset);
    else no_later_cold_reset: assume(!reset);
  end
  reg past_valid = 0, past_reset = 1;
  wire check = past_valid && !reset && !past_reset && !systemReset;
  always @(posedge clock or posedge reset) begin
    if (reset || !initialized) begin
      past_reset <= 1;
      past_valid <= 0;
    end else begin
      past_reset <= reset;
      past_valid <= 1;
    end
  end

  reg [5:0] dmi_phase = 0;
  reg dmi_pending = 0;
  reg [4:0] inactive_wait = 0;
  reg store_accepted = 0;
  wire dmi_accept = dmi_request_valid && dmi_request_ready;
  wire dmi_return = dmi_response_valid && dmi_response_ready;
  wire abstract_poll = dmi_phase == 5 || dmi_phase == 9 || dmi_phase == 11 || dmi_phase == 13 ||
                       dmi_phase == 18 || dmi_phase == 20 || dmi_phase == 24 || dmi_phase == 28 ||
                       dmi_phase == 30 || dmi_phase == 34 || dmi_phase == 37 || dmi_phase == 44 || dmi_phase == 48;
  wire phase_done = dmi_phase == 2 ? dmi_response_bits_data[9:8] == 3 :
                    abstract_poll ? !dmi_response_bits_data[12] &&
                                    (dmi_phase == 9 || dmi_response_bits_data[10:8] == 0) :
                    dmi_phase == 14 ? dmi_response_bits_data == 32'h234 :
                    dmi_phase == 21 ? dmi_response_bits_data == 32'h123 :
                    dmi_phase == 31 ? dmi_response_bits_data == 32'h12345678 : 1'b1;

  always @* begin
    dmi_request_valid = check && dmi_phase < 49 && dmi_phase != 42 &&
                        (dmi_phase != 41 || store_accepted) && !dmi_pending;
    dmi_request_bits_address = 7'h10;
    dmi_request_bits_data = 1;
    dmi_request_bits_op = 2;
    case (dmi_phase)
      1, 43: dmi_request_bits_data = 32'h80000001;
      2, 5, 9, 11, 13, 18, 20, 24, 28, 30, 34, 37, 44, 48: begin
        dmi_request_bits_address = dmi_phase == 2 ? 7'h11 : 7'h16;
        dmi_request_bits_data = 0;
        dmi_request_bits_op = 1;
      end
      3, 22, 32, 35: begin
        dmi_request_bits_address = 4;
        case (dmi_phase)
          3: dmi_request_bits_data = 32'h234;
          22: dmi_request_bits_data = 32'h12345679;
          32: dmi_request_bits_data = 32'h400;
          default: dmi_request_bits_data = 32'h13579bdf;
        endcase
      end
      4, 12, 19, 23, 29, 33, 36: begin
        dmi_request_bits_address = 7'h17;
        case (dmi_phase)
          4: dmi_request_bits_data = 32'h230341;
          12: dmi_request_bits_data = 32'h220341;
          19: dmi_request_bits_data = 32'h221001;
          23: dmi_request_bits_data = 32'h231001;
          29: dmi_request_bits_data = 32'h2207b1;
          33: dmi_request_bits_data = 32'h231001;
          default: dmi_request_bits_data = 32'h231002;
        endcase
      end
      6, 15, 25, 38, 45: begin
        dmi_request_bits_address = 7'h20;
        case (dmi_phase)
          6: dmi_request_bits_data = 32'h0000006f;
          15: dmi_request_bits_data = 32'h00930001;
          25: dmi_request_bits_data = 32'h7b109073;
          38: dmi_request_bits_data = 32'h0020a223;
          default: dmi_request_bits_data = 32'h00000013;
        endcase
      end
      7, 16, 26, 39, 46: begin
        dmi_request_bits_address = 7'h21;
        dmi_request_bits_data = dmi_phase == 16 ? 32'h90021230 : dmi_phase == 46 ? 32'h00000013 : 32'h00100073;
      end
      8, 17, 27, 40, 47: begin
        dmi_request_bits_address = 7'h17;
        dmi_request_bits_data = dmi_phase == 47 ? 32'h00261001 : 32'h00040000;
      end
      10: begin
        dmi_request_bits_address = 7'h16;
        dmi_request_bits_data = 32'h700;
      end
      14, 21, 31: begin
        dmi_request_bits_address = 4;
        dmi_request_bits_data = 0;
        dmi_request_bits_op = 1;
      end
      41: dmi_request_bits_data = 0;
      default: begin end
    endcase
  end

  reg instruction_busy = 0, data_busy = 0;
  reg [31:0] instruction_address = 0, data_address = 0;
  reg [4:0] data_wait = 0;
  assign instruction_request_ready = !instruction_busy;
  assign instruction_response_valid = instruction_busy;
  assign instruction_response_bits_data = 32'h00000013;
  assign instruction_response_bits_fault = 0;
  assign data_request_ready = !data_busy;
  assign data_response_valid = data_busy && data_wait == 15;
  assign data_response_bits_data = 32'h13579bdf;
  assign data_response_bits_fault = 0;
  wire instruction_accept = instruction_request_valid && instruction_request_ready;
  wire instruction_return = instruction_response_valid && instruction_response_ready;
  wire data_accept = data_request_valid && data_request_ready;
  wire data_return = data_response_valid && data_response_ready;

  always @(posedge clock or posedge reset) begin
    if (reset || !initialized) begin
      dmi_phase <= 0;
      dmi_pending <= 0;
      inactive_wait <= 0;
      store_accepted <= 0;
      instruction_busy <= 0;
      data_busy <= 0;
      instruction_address <= 0;
      data_address <= 0;
      data_wait <= 0;
    end else begin
      if (check) begin
        if (dmi_accept) dmi_pending <= dmi_request_bits_op == 1;
        if (dmi_return) begin
          dmi_pending <= 0;
          if (dmi_pending && phase_done && dmi_phase != 41) dmi_phase <= dmi_phase + 1;
        end
        if (dmi_accept && dmi_request_bits_op == 2) dmi_phase <= dmi_phase + 1;
        if (dmi_phase == 42) begin
          inactive_wait <= inactive_wait + 1;
          if (inactive_wait == 31) dmi_phase <= 43;
        end
      end
      if (instruction_accept) begin
        instruction_busy <= 1;
        instruction_address <= instruction_request_bits_address;
      end
      if (instruction_return) instruction_busy <= 0;
      if (data_accept && data_request_bits_write && data_request_bits_address == 32'h404 && dmi_phase == 41)
        store_accepted <= 1;
      if (data_accept) begin
        data_busy <= 1;
        data_address <= data_request_bits_address;
        data_wait <= 0;
      end
      if (data_busy && !data_return) data_wait <= data_wait + 1;
      if (data_return) data_busy <= 0;
    end
  end

  wire injected_local = dut.m_injected && dut.m_csr &&
                        (dut.m_csrAddress == 12'h7b0 || dut.m_csrAddress == 12'h7b1);
  always @(posedge clock) begin
    if (check) begin
      if (dut.m_injected) begin
        injected_not_native_retire: assert(!retire_valid && !retire_writes && retire_rd == 0);
        injected_not_native_trap: assert(!dut.csr.trap);
      end
      if (injected_local) begin
        injected_csr_local: assert(!dut.csr.commit);
        injected_local_operands: assert(dut.debug.core_localCsr_operand == dut.m_csrOperand);
      end
      injected_no_trigger: assert(dut.csr.trigger.core_valid == (dut.xValid && !dut.xInjected));
      if (dut.debug.core_injectionActive)
        injected_backend_quiet: assert(dut.csr.address == dut.m_csrAddress);
      if ($past(!dut.dm.hart_control_active))
        deactivate_blocks_injected_issue: assert(!dut.debug.core_injection_valid);

      cover_halted: cover(dmi_phase == 2 && dmi_return && dmi_response_bits_data[9:8] == 3);
      cover_injected_execution: cover(debugExecution_valid);
      cover_program_fault: cover(dmi_phase == 9 && dmi_return && !dmi_response_bits_data[12] &&
                                 dmi_response_bits_data[10:8] == 3);
      cover_trap_csr_preserved: cover(dmi_phase == 14 && dmi_return && dmi_response_bits_data == 32'h234);
      cover_cross_word: cover(debugExecution_valid && debugExecution_sequence == 1 &&
                              debugExecution_word == 32'h12300093 && debugExecution_length == 4);
      cover_local_dpc_command: cover(dmi_phase == 27 && dmi_accept && dmi_request_bits_address == 7'h17 &&
                                     dmi_request_bits_data == 32'h00040000);
      cover_local_dpc_execution: cover(debugExecution_valid && debugExecution_csr && dut.m_csrAddress == 12'h7b1);
      cover_local_dpc: cover(dmi_phase == 31 && dmi_return && dmi_response_bits_data == 32'h12345678);
      cover_store_program: cover(dmi_phase == 40 && dmi_accept && dmi_request_bits_address == 7'h17 &&
                                 dmi_request_bits_data == 32'h00040000);
      cover_store_accepted: cover(data_accept && data_request_bits_write &&
                                  data_request_bits_address == 32'h404 && dmi_phase == 41);
      cover_store_deactivated: cover(dmi_phase == 42 && !dut.dm.hart_control_active);
      cover_deactivated_store: cover(debugExecution_valid && debugExecution_store && !dut.dm.hart_control_active);
      cover_postexec_transfer: cover(dmi_phase == 47 && dmi_accept && dmi_request_bits_data == 32'h00261001);
      cover_implicit_ebreak: cover(debugExecution_valid && debugExecution_sequence == 4 && debugExecution_ebreak);
    end
  end
endmodule
