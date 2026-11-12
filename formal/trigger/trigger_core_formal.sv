// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module trigger_core_formal #(parameter [1:0] SCENARIO = 0)(input clock, input reset);
  wire [1:0] scenario = SCENARIO;
  wire [31:0] target = scenario == 3 ? 32'd12 : 32'd48;
  wire [31:0] handler = scenario == 3 ? 32'h100 : 32'h38;
  wire [31:0] completion = 32'd52;
  wire [31:0] target_store = scenario == 3 ? 32'h204 : 32'h204;

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
  reg dmi_request_valid, dmi_response_ready = 1;
  reg [6:0] dmi_request_bits_address;
  reg [31:0] dmi_request_bits_data;
  reg [1:0] dmi_request_bits_op;
  wire systemReset;

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
    .debugExecution_valid(), .debugExecution_sequence(), .debugExecution_pc(),
    .debugExecution_word(), .debugExecution_length(), .debugExecution_rd(),
    .debugExecution_writes(), .debugExecution_value(), .debugExecution_fault(),
    .debugExecution_ebreak(), .debugExecution_csr(), .debugExecution_load(),
    .debugExecution_store(), .debugExecution_address(),
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
  reg first_check = 0;
  always @(posedge clock or posedge reset) begin
    if (reset || !initialized) first_check <= 1;
    else if (check) first_check <= 0;
  end

  function [31:0] rom(input [31:0] address);
    case (address)
      0: rom = scenario == 3 ? 32'h10000093 : 32'h00000013;
      4: rom = scenario == 3 ? 32'h30509073 : 32'h00000013;
      8: rom = scenario == 3 ? 32'h20002083 : 32'h00000013;
      12: rom = scenario == 3 ? 32'h20102223 : 32'h00000013;
      16: rom = 32'h00000013;
      20: rom = 32'h00000013;
      24: rom = 32'h00000013;
      28: rom = 32'h00000013;
      32: rom = 32'h00000013;
      36: rom = 32'h00000013;
      40: rom = 32'h00000013;
      44: rom = 32'h20002283;
      48: rom = scenario == 0 ? 32'h20602223 : scenario == 1 ? 32'h026282b3 : 32'hffffffff;
      52: rom = 32'h0000006f;
      56: rom = 32'h341023f3;
      60: rom = 32'h20702823;
      64: rom = 32'h342023f3;
      68: rom = 32'h20702a23;
      72: rom = 32'h343023f3;
      76: rom = 32'h20702c23;
      80: rom = 32'h7a5023f3;
      84: rom = 32'h20702e23;
      88: rom = 32'h7a1023f3;
      92: rom = 32'h22702023;
      96: rom = 32'h7a101073;
      100: rom = 32'h341023f3;
      104: rom = scenario == 2 ? 32'h00438393 : 32'h34139073;
      108: rom = scenario == 2 ? 32'h34139073 : 32'h30200073;
      112: rom = 32'h30200073;
      256: rom = 32'h0000006f;
      512: rom = 32'h11223344;
      default: rom = 32'h0000006f;
    endcase
  endfunction

  reg instruction_busy = 0, data_busy = 0;
  reg [31:0] instruction_address, data_address;
  reg data_write;
  reg [31:0] data_write_data;
  reg [3:0] data_write_mask;
  // DMI setup must let an offered fetch drain before the hart can halt.
  assign instruction_request_ready = check && !instruction_busy;
  assign instruction_response_valid = check && instruction_busy;
  assign instruction_response_bits_data = rom(instruction_address);
  assign instruction_response_bits_fault = 0;
  assign data_request_ready = check && !data_busy;
  assign data_response_valid = check && data_busy;
  assign data_response_bits_data = 32'h11223344;
  assign data_response_bits_fault = scenario == 3 && data_address == 32'h200;
  wire instruction_accept = instruction_request_valid && instruction_request_ready;
  wire instruction_return = instruction_response_valid && instruction_response_ready;
  wire data_accept = data_request_valid && data_request_ready;
  wire data_return = data_response_valid && data_response_ready;

  reg [4:0] dmi_phase = 0;
  reg dmi_pending = 0;
  wire [4:0] execution_phase = scenario == 1 ? 24 : 21;
  wire [31:0] resume_pc = scenario == 3 ? 0 : 44;
  wire dmi_accept = dmi_request_valid && dmi_request_ready;
  wire dmi_return = dmi_response_valid && dmi_response_ready;
  always @* begin
    dmi_request_valid = check && dmi_phase < execution_phase + 1 && !dmi_pending;
    dmi_request_bits_address = 7'h10;
    dmi_request_bits_data = 1;
    dmi_request_bits_op = 2;
    case (dmi_phase)
      1: dmi_request_bits_data = 32'h80000001;
      2, 4, 5, 8, 11, 14, 17, 20, 23: begin
        dmi_request_bits_address = dmi_phase == 2 ? 7'h11 : 7'h16;
        dmi_request_bits_data = 0;
        dmi_request_bits_op = 1;
      end
      3: begin
        dmi_request_bits_address = 7'h16;
        dmi_request_bits_data = 32'h700;
      end
      6, 9, 12, 15, 18: begin
        dmi_request_bits_address = 4;
        case (dmi_phase)
          6: dmi_request_bits_data = target;
          9: dmi_request_bits_data = 32'h20000044;
          12: dmi_request_bits_data = 8;
          15: dmi_request_bits_data = scenario == 1 ? 32'h123 : handler;
          default: dmi_request_bits_data = scenario == 1 ? handler : resume_pc;
        endcase
      end
      7, 10, 13, 16, 19, 22: begin
        dmi_request_bits_address = 7'h17;
        case (dmi_phase)
          7: dmi_request_bits_data = 32'h2307a2;
          10: dmi_request_bits_data = 32'h2307a1;
          13: dmi_request_bits_data = 32'h2307a5;
          16: dmi_request_bits_data = scenario == 1 ? 32'h231006 : 32'h230305;
          19: dmi_request_bits_data = scenario == 1 ? 32'h230305 : 32'h2307b1;
          default: dmi_request_bits_data = 32'h2307b1;
        endcase
      end
      21: begin
        dmi_request_bits_address = scenario == 1 ? 4 : 7'h10;
        dmi_request_bits_data = scenario == 1 ? resume_pc : 32'h40000001;
      end
      24: dmi_request_bits_data = 32'h40000001;
      default: begin end
    endcase
  end
  always @(posedge clock or posedge reset) begin
    if (reset || !initialized) begin
      dmi_phase <= 0;
      dmi_pending <= 0;
    end else if (check) begin
      if (dmi_accept) dmi_pending <= 1;
      if (dmi_return) begin
        dmi_pending <= 0;
        if (dmi_phase == 2) begin
          if (dmi_response_bits_data[9:8] == 3) dmi_phase <= dmi_phase + 1;
        end else if (dmi_phase == 4 || dmi_phase == 5 || dmi_phase == 8 || dmi_phase == 11 ||
                     dmi_phase == 14 || dmi_phase == 17 || dmi_phase == 20 || dmi_phase == 23) begin
          if (!dmi_response_bits_data[12] && dmi_response_bits_data[10:8] == 0) dmi_phase <= dmi_phase + 1;
        end else begin
          dmi_phase <= dmi_phase + 1;
        end
      end
    end
  end

  reg target_trap = 0, target_normal = 0, older_seen = 0, completion_seen = 0;
  reg metadata_epc = 0, metadata_cause = 0, metadata_tval = 0, metadata_control = 0, metadata_hit = 0;
  reg [31:0] retired_multiply_value = 0;
  wire finished = scenario == 3 ? older_seen && completion_seen :
                  completion_seen && metadata_epc && metadata_cause && metadata_tval && metadata_control && metadata_hit;
  always @(posedge clock or posedge reset) begin
    if (reset || !initialized) begin
      instruction_busy <= 0;
      data_busy <= 0;
      instruction_address <= 0;
      data_address <= 0;
      data_write <= 0;
      data_write_data <= 0;
      data_write_mask <= 0;
    end else if (check) begin
      if (instruction_accept) begin
        instruction_busy <= 1;
        instruction_address <= instruction_request_bits_address;
      end
      if (instruction_return) instruction_busy <= 0;
      if (data_accept) begin
        data_busy <= 1;
        data_address <= data_request_bits_address;
        data_write <= data_request_bits_write;
        data_write_data <= data_request_bits_data;
        data_write_mask <= data_request_bits_mask;
      end
      if (data_return) data_busy <= 0;
    end
  end

  always @(posedge clock or posedge reset) begin
    if (reset || !initialized || dmi_phase < execution_phase) begin
      target_trap <= 0;
      target_normal <= 0;
      older_seen <= 0;
      completion_seen <= 0;
      metadata_epc <= 0;
      metadata_cause <= 0;
      metadata_tval <= 0;
      metadata_control <= 0;
      metadata_hit <= 0;
      retired_multiply_value <= 0;
    end else if (check && dmi_phase >= execution_phase) begin
      no_external_event: assert(!systemReset && !interrupt_valid);
      if (data_return) begin
        if (scenario <= 2 && data_write && data_write_mask == 15) begin
          case (data_address)
            32'h210: begin metadata_epc <= 1; native_epc_metadata: assert(data_write_data == target); end
            32'h214: begin metadata_cause <= 1; native_cause_metadata: assert(data_write_data == 3); end
            32'h218: begin metadata_tval <= 1; native_tval_metadata: assert(data_write_data == target); end
            32'h21c: begin metadata_control <= 1; native_control_metadata: assert(data_write_data == 32'h80); end
            32'h220: begin metadata_hit <= 1; native_hit_metadata: assert(data_write_data == 32'h20100044); end
            default: begin end
          endcase
        end
      end
      if (retire_valid && retire_pc == target - 4) older_seen <= 1;
      if (scenario == 3 && retire_valid && retire_pc == 8) begin
        older_seen <= 1;
        older_fault_cause: assert(retire_trap && retire_cause == 5 && retire_tval == 32'h200);
      end
      if (scenario == 3 && retire_valid && retire_pc == handler) completion_seen <= 1;
      if (scenario <= 2 && retire_valid && retire_pc == completion) completion_seen <= 1;
      if (retire_valid && retire_pc == target) begin
        target_first_event_is_breakpoint: assert(target_trap || (retire_trap && retire_cause == 3 &&
                                                 retire_tval == target && retire_nextPc == handler));
        target_retry_has_no_trap: assert(scenario > 1 || !target_trap || !retire_trap);
        target_has_no_writeback_on_trap: assert(!retire_trap || !retire_writes);
        if (scenario <= 1 && target_trap) target_single_retry: assert(!target_normal);
        if (scenario == 2) illegal_single_breakpoint: assert(!target_trap);
        if (scenario <= 1 && target_trap) older_load_retires_first: assert(older_seen);
        if (scenario <= 1) target_normal <= target_trap;
        target_trap <= 1;
      end
      older_fault_blocks_target: assert(scenario != 3 || !retire_valid || retire_pc != target);
      no_store_before_breakpoint: assert(!data_request_valid || !data_request_bits_write ||
        data_request_bits_address != target_store || scenario != 0 || target_trap);
      older_fault_blocks_store: assert(scenario != 3 || !data_request_valid || !data_request_bits_write ||
        data_request_bits_address != target_store);
      no_multiply_before_breakpoint: assert(scenario != 1 || !mulDiv_start || target_trap);
      multiply_has_target_identity: assert(scenario != 1 || !mulDiv_start || mulDiv_pc == target);
      if (scenario == 1 && retire_valid && retire_pc == target && !retire_trap)
        retired_multiply_value <= retire_value;
      cover_target_breakpoint: cover(scenario <= 2 && retire_valid && retire_pc == target && retire_trap && retire_nextPc == handler);
      cover_older_fault_event: cover(scenario == 3 && retire_valid && retire_pc == 8 && retire_trap && retire_cause == 5 && retire_tval == 32'h200);
      cover_older_load_accepted: cover(scenario == 3 && data_accept && !data_request_bits_write && data_request_bits_address == 32'h200);
      cover_native_epc: cover(scenario <= 2 && data_return && data_write && data_address == 32'h210 && data_write_data == target);
      cover_native_cause: cover(scenario <= 2 && data_return && data_write && data_address == 32'h214 && data_write_data == 3);
      cover_native_tval: cover(scenario <= 2 && data_return && data_write && data_address == 32'h218 && data_write_data == target);
      cover_native_control: cover(scenario <= 2 && data_return && data_write && data_address == 32'h21c && data_write_data == 32'h80);
      cover_native_hit: cover(scenario <= 2 && data_return && data_write && data_address == 32'h220 && data_write_data == 32'h20100044);
      cover_multiply_start: cover(scenario == 1 && mulDiv_start);
      cover_multiply_done: cover(scenario == 1 && mulDiv_finish);
      cover_target_normal: cover(scenario <= 1 && retire_valid && retire_pc == target && !retire_trap);
      cover_target_retry: cover(scenario <= 1 && target_trap && retire_valid && retire_pc == target && !retire_trap);
      cover_multiply_value: cover(scenario == 1 && retire_valid && retire_pc == target && !retire_trap && retire_value == 32'h79e0464c);
      cover_completion: cover(scenario <= 2 && retire_valid && retire_pc == completion);
      cover_metadata_complete: cover(scenario <= 2 && metadata_epc && metadata_cause && metadata_tval && metadata_control && metadata_hit);
      cover_store_finish: cover(finished && scenario == 0);
      cover_multiply_finish: cover(finished && scenario == 1 && retired_multiply_value == 32'h79e0464c);
      cover_illegal_finish: cover(finished && scenario == 2);
      cover_older_fault: cover(finished && scenario == 3);
    end
  end

  always @(posedge clock) begin
    if (check) begin
      if (dmi_phase == 0 && first_check) initial_dpc_zero: assert(dut.debug.dpc == 0);
      if (dmi_phase == execution_phase && dut.debug.core_resume) abstract_dpc_value: assert(dut.debug.dpc == resume_pc);
      if (dmi_phase == execution_phase && dut.debug.core_resume) resume_pc_matches: assert(dut.debug.core_resumePc == resume_pc);
      cover_resume_dpc: cover(dmi_phase == execution_phase && dut.debug.core_resume && dut.debug.core_resumePc == resume_pc);
      cover_first_dmi: cover(dmi_accept && past_valid && !past_reset && dut.debug.dpc == 0);
    end
  end

  always @(posedge clock) begin
    cover_cold_reset: cover(dmi_phase == 0 && first_check && dut.debug.dpc == 0);
  end
endmodule
