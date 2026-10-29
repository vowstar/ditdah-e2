// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module debug_core_formal #(parameter TARGET = 0)(input clock);
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyconst *) reg [1:0] scenario;
  wire [1:0] instruction_delay = 0;
  (* anyconst *) reg [1:0] initial_delay, stepped_delay;
  wire [1:0] data_delay = data_count == 0 ? initial_delay : stepped_delay;
  wire instruction_request_valid, instruction_request_ready;
  wire [31:0] instruction_request_bits_address, instruction_request_bits_data;
  wire instruction_request_bits_write, instruction_request_bits_machine;
  wire data_request_bits_machine, retire_userMode;
  wire [3:0] instruction_request_bits_operation, data_request_bits_operation;
  wire [3:0] instruction_request_bits_mask;
  wire [1:0] instruction_request_bits_size;
  wire instruction_response_valid, instruction_response_ready, instruction_response_bits_fault;
  wire [31:0] instruction_response_bits_data;
  wire data_request_valid, data_request_ready, data_request_bits_write;
  wire [31:0] data_request_bits_address, data_request_bits_data;
  wire [3:0] data_request_bits_mask;
  wire [1:0] data_request_bits_size;
  wire data_response_valid, data_response_ready, data_response_bits_fault;
  wire [31:0] data_response_bits_data;
  wire retire_valid, retire_writes, retire_trap;
  wire [31:0] retire_pc, retire_word, retire_nextPc, retire_value, retire_cause, retire_tval;
  wire [4:0] retire_rd;
  wire loadUse, forward, redirect, memoryWait;
  wire interrupts_software = 0, interrupts_timer = 0, interrupts_external = 0;
  wire [63:0] timeValue = 0;
  wire interrupt_valid, sleeping;
  wire [31:0] interrupt_pc, interrupt_target, interrupt_cause;
  wire mulDiv_start, mulDiv_resultValid, mulDiv_finish, mulDiv_cancel;
  wire [31:0] mulDiv_pc, mulDiv_value;

  wire dmi_request_ready, dmi_response_valid, systemReset;
  reg dmi_request_valid;
  reg [6:0] dmi_request_bits_address;
  reg [31:0] dmi_request_bits_data;
  reg [1:0] dmi_request_bits_op;
  wire dmi_response_ready = 1;
  wire [31:0] dmi_response_bits_data;
  wire [1:0] dmi_response_bits_status;
  wire observed_halted, observed_resume, observed_step;
  wire [31:0] observed_dpc;
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

  function [31:0] rom(input [31:0] address);
    case (address)
      0: rom = 32'h10000193;
      4: rom = 32'h30519073;
      8: rom = 32'h20002083;
      12: rom = 32'h00900113;
      64: rom = scenario <= 1 ? 32'h20002283 :
                scenario == 2 ? 32'hffffffff : 32'h00700293;
      68: rom = 32'h00100313;
      256: rom = 32'h00100393;
      512: rom = 32'h12345678;
      default: rom = 32'h0000006f;
    endcase
  endfunction

  reg instruction_busy = 0, data_busy = 0;
  reg [1:0] instruction_wait = 0, data_wait = 0;
  reg [31:0] instruction_address;
  reg data_fault = 0;
  reg [1:0] data_count = 0;
  assign instruction_request_ready = !instruction_busy;
  assign instruction_response_valid = instruction_busy && instruction_wait == 0;
  assign instruction_response_bits_data = rom(instruction_address);
  assign instruction_response_bits_fault = 0;
  assign data_request_ready = !data_busy;
  assign data_response_valid = data_busy && data_wait == 0;
  assign data_response_bits_data = 32'h12345678;
  assign data_response_bits_fault = data_fault;
  wire instruction_accept = instruction_request_valid && instruction_request_ready;
  wire instruction_return = instruction_response_valid && instruction_response_ready;
  wire data_accept = data_request_valid && data_request_ready;
  wire data_return = data_response_valid && data_response_ready;

  reg [3:0] phase = 0;
  reg dmi_pending = 0;
  reg saw_data = 0, saw_delayed_halt = 0, first_halt = 0;
  reg step_started = 0, finished = 0, saw_initial_fault = 0, saw_step_fault = 0;
  reg [1:0] step_count = 0;
  reg [7:0] cycle = 0;
  reg [31:0] expected_pc = 0;
  wire dmi_accept = dmi_request_valid && dmi_request_ready;
  wire dmi_return = dmi_response_valid && dmi_response_ready;
  always @* begin
    dmi_request_valid = !reset && !dmi_pending && phase != 11 && (phase != 1 || saw_data);
    dmi_request_bits_address = 7'h10;
    dmi_request_bits_data = 1;
    dmi_request_bits_op = 2;
    case (phase)
      1: dmi_request_bits_data = 32'h80000001;
      2, 10: begin dmi_request_bits_address = 7'h11; dmi_request_bits_op = 1; end
      3: begin dmi_request_bits_address = 4; dmi_request_bits_data = 64; end
      4: begin dmi_request_bits_address = 7'h17; dmi_request_bits_data = 32'h002307b1; end
      5, 8: begin dmi_request_bits_address = 7'h16; dmi_request_bits_op = 1; end
      6: begin dmi_request_bits_address = 4; dmi_request_bits_data = 7; end
      7: begin dmi_request_bits_address = 7'h17; dmi_request_bits_data = 32'h002307b0; end
      9: dmi_request_bits_data = 32'h40000001;
      default: begin end
    endcase
  end

  wire early_halt = observed_halted && (data_busy || instruction_busy);
  wire extra_step = step_started && retire_valid && step_count != 0;
  wire expected_trap = (expected_pc == 8 && scenario == 3) ||
                       (expected_pc == 64 && (scenario == 1 || scenario == 2));
  wire [31:0] expected_next = expected_trap ? 256 :
                            rom(expected_pc) == 32'h0000006f ? expected_pc : expected_pc + 4;
  always @(posedge clock) begin
    if (!reset) begin
      cycle <= cycle + 1;
      assert(!systemReset && !interrupt_valid);
      assert(!early_halt);
      assert(!extra_step);
      assert(!observed_halted || !retire_valid);
      if (instruction_accept) begin
        assert(!instruction_busy);
        instruction_busy <= 1;
        instruction_address <= instruction_request_bits_address;
        instruction_wait <= instruction_delay == 3 ? 2 : instruction_delay;
      end
      if (instruction_busy && instruction_wait != 0) instruction_wait <= instruction_wait - 1;
      if (instruction_return) instruction_busy <= 0;
      if (data_accept) begin
        assert(!data_busy);
        assert(data_request_bits_address == 512 && !data_request_bits_write);
        assert(data_request_bits_size == 2 && data_request_bits_mask == 0);
        assert(data_request_bits_machine && data_request_bits_operation == 0);
        data_busy <= 1;
        data_wait <= data_delay == 3 ? 2 : data_delay;
        data_fault <= (scenario == 3 && data_count == 0) || (scenario == 1 && data_count == 1);
        data_count <= data_count + 1;
        saw_data <= 1;
      end
      if (data_busy && data_wait != 0) data_wait <= data_wait - 1;
      if (data_return) begin
        data_busy <= 0;
        assert(retire_valid && retire_pc == (data_count == 1 ? 8 : 64));
      end
      if (((phase == 1 && dmi_pending) || phase >= 2) && data_busy && !data_return && !step_started) saw_delayed_halt <= 1;
      if (dmi_accept) begin assert(!dmi_pending); dmi_pending <= 1; end
      if (dmi_return) begin
        assert(dmi_pending && dmi_response_bits_status == 0);
        dmi_pending <= 0;
        case (phase)
          2: if (dmi_response_bits_data[9:8] == 3) phase <= 3;
          5, 8: begin
            assert(dmi_response_bits_data[10:8] == 0);
            if (!dmi_response_bits_data[12]) phase <= phase + 1;
          end
          10: if (dmi_response_bits_data[9:8] == 3 && dmi_response_bits_data[17:16] == 3) phase <= 11;
          default: phase <= phase + 1;
        endcase
      end
      if (observed_halted && !first_halt) begin
        assert(observed_dpc == expected_pc);
        if (scenario == 3) assert(observed_dpc == 256);
        first_halt <= 1;
      end
      if (observed_resume) begin
        assert(first_halt && !step_started && observed_dpc == 64);
        assert(!retire_valid);
        step_started <= 1;
        expected_pc <= 64;
      end
      if (retire_valid) begin
        assert(retire_pc == expected_pc && retire_word == rom(expected_pc));
        assert(retire_trap == expected_trap && retire_nextPc == expected_next);
        if (expected_pc == 8 || (expected_pc == 64 && scenario <= 1)) assert(data_return);
        if (expected_pc == 8 && !expected_trap) assert(retire_writes && retire_rd == 1 && retire_value == 32'h12345678);
        if (expected_trap) begin
          assert(!retire_writes && retire_cause == (scenario == 2 && step_started ? 2 : 5));
          assert(retire_tval == (scenario == 2 && step_started ? 32'hffffffff : 512));
          if (step_started) saw_step_fault <= 1;
          else saw_initial_fault <= 1;
        end
        if (step_started) begin
          assert(observed_step);
          step_count <= step_count + 1;
          assert(retire_pc == 64);
          if (!expected_trap) assert(retire_writes && retire_rd == 5 && retire_value == (scenario == 0 ? 32'h12345678 : 7));
        end
        expected_pc <= expected_next;
      end
      if (observed_halted && step_started) begin
        assert(step_count == 1 && observed_dpc == expected_pc);
        assert(observed_dpc == (scenario == 1 || scenario == 2 ? 256 : 68));
        finished <= 1;
      end
      if (cycle == 59) assert(finished && phase == 11);
`ifdef REACHABILITY
      assert(!(finished && phase == 11 && scenario == TARGET && (TARGET != 0 || saw_delayed_halt)));
`endif
    end
  end
endmodule
