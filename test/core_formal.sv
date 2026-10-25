// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module core_formal(input clock);
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyconst *) reg [1:0] younger;
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
  wire loadUse, forward, redirect, memoryWait;
  wire interrupts_software = 0, interrupts_timer = 0, interrupts_external = 0;
  wire [63:0] timeValue = 0;
  wire interrupt_valid, sleeping;
  wire [31:0] interrupt_pc, interrupt_target, interrupt_cause;
  wire mulDiv_start, mulDiv_resultValid, mulDiv_finish, mulDiv_cancel;
  wire [31:0] mulDiv_pc, mulDiv_value;
  DitDahE2 dut (.*);

  function [31:0] rom(input [31:0] address);
    case (address)
      0: rom = 32'h305c5073;  // csrrwi x0, mtvec, 24
      4: rom = 32'h3404d073;  // csrrwi x0, mscratch, 9
      8: rom = 32'h30046073;  // csrrsi x0, mstatus, 8
      12: rom = 32'h10002183; // lw x3, 256(x0)
      16: case (younger)
        0: rom = 32'h10002223; // sw x0, 260(x0)
        1: rom = 32'h3403d073; // csrrwi x0, mscratch, 7
        default: rom = 32'h30200073; // mret
      endcase
      24: rom = 32'h34002273; // csrrs x4, mscratch, x0
      28: rom = 32'h341022f3; // csrrs x5, mepc, x0
      32: rom = 32'h34202373; // csrrs x6, mcause, x0
      36: rom = 32'h343023f3; // csrrs x7, mtval, x0
      40: rom = 32'h30002473; // csrrs x8, mstatus, x0
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
  assign data_response_bits_data = 32'hbad0cafe;
  assign data_response_bits_fault = 1;
  wire instruction_request = instruction_request_valid && instruction_request_ready;
  wire instruction_response = instruction_response_valid && instruction_response_ready;
  wire data_request = data_request_valid && data_request_ready;
  wire data_response = data_response_valid && data_response_ready;

`ifdef REACHABILITY
  always @(posedge clock) begin
    assume(accept_instruction && accept_data);
    assume(release_instruction == (instruction_address != 16 || data_busy));
    assume(release_data == (data_age >= 6));
  end
`endif

  reg past_valid = 0, saw_request = 0, saw_fault = 0, saw_younger = 0, delayed_younger = 0;
  reg [1:0] younger_age = 0;
  reg [3:0] event_index = 0;
  reg [31:0] expected_pc, expected_next, expected_value;
  reg [4:0] expected_rd;
  always @* begin
    expected_pc = event_index < 4 ? {26'b0, event_index, 2'b0} :
                  event_index < 9 ? 24 + ((event_index - 4) << 2) : 44;
    expected_next = event_index == 3 ? 24 : event_index == 9 ? 44 : expected_pc + 4;
    expected_rd = event_index >= 4 && event_index <= 8 ? event_index : 0;
    expected_value = 0;
    case (event_index)
      4: expected_value = 9;
      5: expected_value = 12;
      6: expected_value = 5;
      7: expected_value = 256;
      8: expected_value = 32'h1880;
    endcase
  end

  always @(posedge clock) begin
    past_valid <= 1;
    assume(younger < 3);
    if (reset) begin
      instruction_busy <= 0;
      instruction_released <= 0;
      data_busy <= 0;
      data_released <= 0;
      data_age <= 0;
      saw_request <= 0;
      saw_fault <= 0;
      saw_younger <= 0;
      delayed_younger <= 0;
      younger_age <= 0;
      event_index <= 0;
    end else begin
      assert(!interrupt_valid && !sleeping);
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
        if (instruction_address == 16 && data_busy && !data_response) saw_younger <= 1;
      end
      if (data_request) begin
        assert(!data_busy && !saw_request);
        data_busy <= 1;
        data_released <= 0;
        data_age <= 0;
        saw_request <= 1;
      end
      if (data_busy && data_age != 15) data_age <= data_age + 1;
      if (data_response_valid) data_released <= 1;
      if (saw_younger && younger_age != 3) younger_age <= younger_age + 1;
      if (data_response) begin
        assert(data_busy && saw_request && !saw_fault);
        assert(retire_valid && retire_trap && retire_pc == 12);
        data_busy <= 0;
        saw_fault <= 1;
        delayed_younger <= saw_younger && younger_age >= 2;
      end
      if (instruction_request_valid) begin
        assert(!instruction_request_bits_write && instruction_request_bits_mask == 0);
        assert(instruction_request_bits_size == 2 && instruction_request_bits_address[1:0] == 0);
      end
      if (data_request_valid) begin
        assert(!data_busy);
        assert(!data_request_bits_write && data_request_bits_address == 256);
        assert(data_request_bits_mask == 0 && data_request_bits_size == 2);
      end
      assert(!data_response_ready || data_busy);
      if (past_valid && !$past(reset)) begin
        if ($past(instruction_request_valid && !instruction_request_ready)) begin
          assert(instruction_request_valid);
          assert($stable({instruction_request_bits_address, instruction_request_bits_write,
                          instruction_request_bits_data, instruction_request_bits_mask,
                          instruction_request_bits_size, instruction_request_bits_machine}));
        end
        if ($past(data_request_valid && !data_request_ready)) begin
          assert(data_request_valid);
          assert($stable({data_request_bits_address, data_request_bits_write,
                          data_request_bits_data, data_request_bits_mask, data_request_bits_size, data_request_bits_machine}));
        end
      end
      if (retire_valid) begin
        assert(retire_pc == expected_pc && retire_word == rom(expected_pc));
        assert(retire_nextPc == expected_next);
        assert(retire_trap == (event_index == 3));
        assert(retire_writes == (expected_rd != 0));
        assert(retire_value == expected_value);
        if (retire_writes) assert(retire_rd == expected_rd);
        if (event_index == 3) begin
          assert(data_response && !retire_writes);
          assert(retire_cause == 5 && retire_tval == 256);
        end
        if (event_index != 9) event_index <= event_index + 1;
      end
      cover(saw_request && data_busy && data_age >= 3);
      cover(saw_fault && delayed_younger);
      cover(event_index == 9 && delayed_younger && younger == 0);
      cover(event_index == 9 && delayed_younger && younger == 1);
      cover(event_index == 9 && delayed_younger && younger == 2);
    end
  end
endmodule
