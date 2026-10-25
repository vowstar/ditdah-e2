// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module interrupt_formal #(parameter integer SCENARIO = -1)(input clock);
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyconst *) reg [2:0] pending_sources, scenario_choice;
  wire [2:0] scenario = SCENARIO < 0 ? scenario_choice : SCENARIO[2:0];
  (* anyseq *) reg accept_instruction, release_instruction, accept_data, release_data;
  wire instruction_request_valid, instruction_request_ready;
  wire [31:0] instruction_request_bits_address, instruction_request_bits_data;
  wire instruction_request_bits_write, instruction_request_bits_machine;
  wire data_request_bits_machine, retire_userMode;
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
  wire loadUse, forward, redirect, memoryWait, sleeping, interrupt_valid;
  wire [31:0] interrupt_pc, interrupt_target, interrupt_cause;
  wire mulDiv_start, mulDiv_resultValid, mulDiv_finish, mulDiv_cancel;
  wire [31:0] mulDiv_pc, mulDiv_value;
  reg irq_active = 0;
  wire interrupts_software = irq_active && pending_sources[0];
  wire interrupts_timer = irq_active && pending_sources[1];
  wire interrupts_external = irq_active && pending_sources[2];
  wire [63:0] timeValue = 0;
  wire wfi_case = scenario == 2 || scenario == 3;
  wire [31:0] expected_cause = pending_sources[2] ? 32'h8000000b :
                              pending_sources[0] ? 32'h80000003 : 32'h80000007;
  DitDahE2 dut (.*);

  function [31:0] rom(input [31:0] address);
    case (address)
      0: rom = 32'h08000093;
      4: rom = 32'h30509073;
      8: rom = 32'h00001137;
      12: rom = 32'h88810113;
      16: rom = 32'h30411073;
      20: rom = scenario == 2 ? 32'h30047073 : 32'h30046073;
      24: rom = wfi_case ? 32'h10500073 : scenario == 4 ? 32'h10002023 : 32'h10002183;
      28: rom = 32'h02a00213;
      128: rom = 32'h341022f3;
      132: rom = 32'h34202373;
      136: rom = 32'h343023f3;
      140: rom = 32'h30002473;
      default: rom = 32'h0000006f;
    endcase
  endfunction

  reg instruction_busy = 0, instruction_released = 0;
  reg [31:0] instruction_address;
  reg data_busy = 0, data_released = 0;
  reg [3:0] data_age = 0;
  assign instruction_request_ready = !instruction_busy && accept_instruction;
  assign instruction_response_valid = instruction_busy && (instruction_released || release_instruction);
  assign instruction_response_bits_data = rom(instruction_address);
  assign instruction_response_bits_fault = 0;
  assign data_request_ready = !data_busy && accept_data;
  assign data_response_valid = data_busy && data_age >= 3 && (data_released || release_data);
  assign data_response_bits_data = 32'h55667788;
  assign data_response_bits_fault = scenario == 1;
  wire instruction_request = instruction_request_valid && instruction_request_ready;
  wire instruction_response = instruction_response_valid && instruction_response_ready;
  wire data_request = data_request_valid && data_request_ready;
  wire data_response = data_response_valid && data_response_ready;

`ifdef REACHABILITY
  always @(posedge clock) begin
    assume(accept_instruction && release_instruction && accept_data);
    assume(release_data == (data_age >= 4));
  end
`endif

  reg past_valid = 0, saw_request = 0, saw_response = 0, saw_wfi = 0, saw_sleep = 0;
  reg entered = 0, handler_complete = 0, resumed = 0;
  reg [1:0] sleep_age = 0;
  reg [31:0] expected_pc = 0;
  reg [31:0] expected_next, expected_value;
  reg [4:0] expected_rd;
  wire expected_trap = expected_pc == 24 && scenario == 1;
  always @* begin
    expected_next = expected_trap ? 128 : expected_pc == 32 || expected_pc == 144 ? expected_pc : expected_pc + 4;
    expected_rd = 0;
    expected_value = 0;
    case (expected_pc)
      0: begin expected_rd = 1; expected_value = 128; end
      8: begin expected_rd = 2; expected_value = 4096; end
      12: begin expected_rd = 2; expected_value = 32'h888; end
      24: if (scenario == 0) begin expected_rd = 3; expected_value = 32'h55667788; end
      28: begin expected_rd = 4; expected_value = 42; end
      128: begin expected_rd = 5; expected_value = scenario == 1 ? 24 : 28; end
      132: begin expected_rd = 6; expected_value = scenario == 1 ? 5 : expected_cause; end
      136: begin expected_rd = 7; expected_value = scenario == 1 ? 256 : 0; end
      140: begin expected_rd = 8; expected_value = 32'h1880; end
    endcase
  end

  always @(posedge clock) begin
    past_valid <= 1;
    assume(scenario < 5);
    assume(pending_sources != 0);
    if (reset) begin
      instruction_busy <= 0;
      instruction_released <= 0;
      data_busy <= 0;
      data_released <= 0;
      data_age <= 0;
      irq_active <= 0;
      saw_request <= 0;
      saw_response <= 0;
      saw_wfi <= 0;
      saw_sleep <= 0;
      entered <= 0;
      handler_complete <= 0;
      resumed <= 0;
      sleep_age <= 0;
      expected_pc <= 0;
    end else begin
      if (instruction_request) begin
        assert(!instruction_busy);
        instruction_busy <= 1;
        instruction_address <= instruction_request_bits_address;
        instruction_released <= 0;
      end
      if (instruction_response_valid) instruction_released <= 1;
      if (instruction_response) begin
        assert(instruction_busy);
        instruction_busy <= 0;
      end
      if (data_request) begin
        assert(!data_busy && !saw_request && !wfi_case);
        data_busy <= 1;
        data_released <= 0;
        data_age <= 0;
        saw_request <= 1;
        irq_active <= 1;
      end
      if (data_busy && data_age != 15) data_age <= data_age + 1;
      if (data_response_valid) data_released <= 1;
      if (data_response) begin
        assert(data_busy && saw_request && !saw_response);
        assert(retire_valid && retire_pc == 24);
        assert(retire_trap == (scenario == 1));
        data_busy <= 0;
        saw_response <= 1;
      end
      if (sleeping) begin
        assert(wfi_case && saw_wfi && !retire_valid && !data_request_valid);
        saw_sleep <= 1;
        if (sleep_age != 3) sleep_age <= sleep_age + 1;
        if (sleep_age >= 1) irq_active <= 1;
      end
      if (data_busy || data_request_valid) assert(!interrupt_valid);
      if (scenario == 1 || scenario == 2) assert(!interrupt_valid);
      assert(!data_response_ready || data_busy);
      if (instruction_request_valid) begin
        assert(!instruction_request_bits_write && instruction_request_bits_mask == 0);
        assert(instruction_request_bits_size == 2 && instruction_request_bits_address[1:0] == 0);
      end
      if (data_request_valid) begin
        assert(!data_busy && data_request_bits_address == 256);
        assert(data_request_bits_write == (scenario == 4));
        assert(data_request_bits_mask == (scenario == 4 ? 15 : 0) && data_request_bits_size == 2);
        if (data_request_bits_write) assert(data_request_bits_data == 0);
      end
      if (past_valid && !$past(reset)) begin
        if ($past(instruction_request_valid && !instruction_request_ready)) begin
          assert(instruction_request_valid);
          assert($stable({instruction_request_bits_address, instruction_request_bits_write,
                          instruction_request_bits_data, instruction_request_bits_mask, instruction_request_bits_size, instruction_request_bits_machine}));
        end
        if ($past(data_request_valid && !data_request_ready)) begin
          assert(data_request_valid);
          assert($stable({data_request_bits_address, data_request_bits_write,
                          data_request_bits_data, data_request_bits_mask, data_request_bits_size, data_request_bits_machine}));
        end
        if ($past(data_response && !data_response_bits_fault)) assert(interrupt_valid);
        if ($past(data_response && data_response_bits_fault)) assert(!interrupt_valid);
        if ($past(sleeping && irq_active)) assert(!sleeping);
      end
      if (interrupt_valid) begin
        assert(!retire_valid && !entered && irq_active);
        assert(wfi_case ? saw_sleep : saw_response);
        assert(interrupt_pc == 28 && expected_pc == 28);
        assert(interrupt_target == 128 && interrupt_cause == expected_cause);
        entered <= 1;
        expected_pc <= 128;
      end
      if (retire_valid) begin
        assert(retire_pc == expected_pc && retire_word == rom(expected_pc));
        assert(retire_nextPc == expected_next && retire_trap == expected_trap);
        assert(retire_writes == (expected_rd != 0) && retire_value == expected_value);
        if (retire_writes) assert(retire_rd == expected_rd);
        if (expected_pc == 24) begin
          if (wfi_case) saw_wfi <= 1;
          else assert(data_response);
        end
        if (expected_trap) begin
          assert(!interrupt_valid && retire_cause == 5 && retire_tval == 256);
          entered <= 1;
        end
        if (expected_pc == 28) begin
          assert(scenario == 2 && saw_sleep && irq_active && !entered);
          resumed <= 1;
        end
        if (expected_pc == 140) begin
          assert(entered);
          handler_complete <= 1;
        end
        expected_pc <= expected_next;
      end
      cover(scenario == 0 && data_busy && irq_active && data_age >= 3 && !data_response);
      cover(scenario == 0 && handler_complete && pending_sources == 1);
      cover(scenario == 0 && handler_complete && pending_sources == 2);
      cover(scenario == 0 && handler_complete && pending_sources == 4);
      cover(scenario == 0 && handler_complete && pending_sources == 7);
      cover(scenario == 1 && handler_complete && pending_sources == 7);
      cover(scenario == 2 && resumed && !sleeping);
      cover(scenario == 3 && handler_complete && saw_sleep);
      cover(scenario == 4 && handler_complete && saw_response);
    end
  end
endmodule
