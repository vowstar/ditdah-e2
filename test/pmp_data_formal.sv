// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module pmp_data_formal(input clock);
  parameter SCENARIO = 0;
  reg reset = 1;
  always @(posedge clock) reset <= 0;
`ifdef UNRESTRICTED_PEER
  (* anyseq *) reg accept_instruction, release_instruction, accept_data, release_data;
`else
  (* anyconst *) reg [1:0] data_accept_delay, data_response_delay;
  reg [1:0] data_offer_age = 0, data_response_age = 0;
  wire accept_instruction = 1, release_instruction = 1;
  wire accept_data = data_offer_age == (data_accept_delay == 0 ? 1 : data_accept_delay);
  wire release_data = data_response_age == data_response_delay;
  always @(posedge clock) begin
    if (reset || !data_request_valid || data_request_ready) data_offer_age <= 0;
    else if (data_offer_age != 3) data_offer_age <= data_offer_age + 1;
    if (reset || !data_busy || data_response_valid) data_response_age <= 0;
    else if (data_response_age != 3) data_response_age <= data_response_age + 1;
  end
`endif
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
  wire loadUse, forward, redirect, memoryWait, sleeping, interrupt_valid;
  wire [31:0] interrupt_pc, interrupt_target, interrupt_cause;
  wire interrupts_software = 0, interrupts_timer = 0, interrupts_external = 0;
  wire [63:0] timeValue = 0;
  wire mulDiv_start, mulDiv_resultValid, mulDiv_finish, mulDiv_cancel;
  wire [31:0] mulDiv_pc, mulDiv_value;
  wire reservationClear, dataDebug;
  wire dmi_request_valid = 0, dmi_response_ready = 1;
  wire [6:0] dmi_request_bits_address = 0;
  wire [31:0] dmi_request_bits_data = 0;
  wire [1:0] dmi_request_bits_op = 0;
  wire dmi_request_ready, dmi_response_valid, systemReset;
  wire [31:0] dmi_response_bits_data;
  wire [1:0] dmi_response_bits_status;
  wire [127:0] observed_configs;
  wire [479:0] observed_addresses;
  wire observed_csr_write, observed_trap, observed_mret, observed_machine;
  wire observed_active, observed_store, observed_sent;
  wire observed_user, observed_mpp_user, observed_mprv;
  wire observed_m_valid, observed_m_csr, observed_m_system, observed_m_return;
  wire observed_complete, observed_advance;
  wire observed_allowed;
  wire [31:0] observed_m_word;
  wire [11:0] observed_csr_address;
  wire [31:0] observed_csr_data, observed_address, observed_pc, observed_mtvec;
  wire [1:0] observed_size;
  DitDahE2 dut (.*);

  localparam MACHINE = SCENARIO >= 2;
  localparam STORE = SCENARIO % 2;
  localparam CONFIG = MACHINE ? 32'h900f : 32'h100f;
  localparam CAUSE = STORE ? 7 : 5;
  localparam BODY_INDEX = MACHINE ? 11 : 14;
  localparam HANDLER_INDEX = BODY_INDEX + 2;
  localparam FINAL_INDEX = HANDLER_INDEX + 5;

  reg [7:0] shadow_cfg [0:15];
  reg [29:0] shadow_addr [0:15];
  reg shadow_user = 0, shadow_mpp_user = 0, shadow_mprv = 0;
  reg [31:0] shadow_mtvec = 0;
  wire shadow_machine = !shadow_user && !(shadow_mprv && shadow_mpp_user);
  wire [127:0] shadow_configs;
  wire [479:0] shadow_addresses;
  genvar slot;
  generate for (slot = 0; slot < 16; slot = slot + 1) begin
    assign shadow_configs[slot*8+:8] = shadow_cfg[slot];
    assign shadow_addresses[slot*30+:30] = shadow_addr[slot];
  end endgenerate
  wire shadow_configured = shadow_cfg[0] == 8'h0f && shadow_addr[0] == 1024 &&
      shadow_cfg[1] == (MACHINE ? 8'h90 : 8'h10) && shadow_addr[1] == 1024 && shadow_configs[127:16] == 0;
  wire [32:0] access_end = {1'b0, observed_address} + (observed_size == 0 ? 1 : observed_size == 1 ? 2 : 4);
  wire interval_permission = observed_size != 3 && access_end <= 33'h100000000 &&
      (observed_address < 4096 ? access_end <= 4096 :
       observed_address < 4100 ? access_end <= 4100 && shadow_machine && !MACHINE : shadow_machine);
  wire shadow_denied = shadow_configured && observed_active && !interval_permission;
  function [7:0] legal_configuration(input [7:0] value);
    legal_configuration = value & (value[0] ? 8'h9f : 8'h9d);
  endfunction
  integer index;
  always @(posedge clock) begin
    if (reset) begin
      for (index = 0; index < 16; index = index + 1) begin
        shadow_cfg[index] <= 0;
        shadow_addr[index] <= 0;
      end
      shadow_user <= 0;
      shadow_mpp_user <= 0;
      shadow_mprv <= 0;
      shadow_mtvec <= 0;
    end else begin
      if (observed_csr_write) begin
        for (index = 0; index < 16; index = index + 1) begin
          if (observed_csr_address == 12'h3a0 + index / 4 && !shadow_cfg[index][7])
            shadow_cfg[index] <= legal_configuration(observed_csr_data[(index % 4)*8+:8]);
          if (observed_csr_address == 12'h3b0 + index && !shadow_cfg[index][7] &&
              (index == 15 || (shadow_cfg[index+1] & 8'h98) != 8'h88))
            shadow_addr[index] <= observed_csr_data[29:0];
        end
        if (observed_csr_address == 12'h305) shadow_mtvec <= observed_csr_data & 32'hfffffffc;
      end
      if (observed_trap) begin
        shadow_user <= 0;
        shadow_mpp_user <= shadow_user;
      end else if (observed_mret) begin
        shadow_user <= shadow_mpp_user;
        shadow_mpp_user <= 1;
        if (shadow_mpp_user) shadow_mprv <= 0;
      end else if (observed_csr_write && observed_csr_address == 12'h300) begin
        shadow_mpp_user <= observed_csr_data[12:11] == 0;
        shadow_mprv <= observed_csr_data[17];
      end
`ifdef SHADOW_CONTRACT
      // BEGIN CONTRACT bank
      assert(observed_configs == shadow_configs && observed_addresses == shadow_addresses);
      assert(observed_machine == shadow_machine && observed_user == shadow_user &&
             observed_mpp_user == shadow_mpp_user && observed_mprv == shadow_mprv);
      // END CONTRACT bank
      // BEGIN CONTRACT decode
      assert(!observed_active || !observed_m_system);
      assert(!observed_m_valid || !observed_m_csr || (observed_m_word[6:0] == 7'h73 &&
             observed_m_word[14:12] != 0 && observed_csr_address == observed_m_word[31:20]));
      assert(!observed_m_valid || !observed_m_return || observed_m_word == 32'h30200073);
      // END CONTRACT decode
      // BEGIN CONTRACT hold
      if (past_valid && !$past(reset) && $past(observed_active && observed_allowed && !data_response)) begin
        assert(observed_active);
        assert($stable({observed_configs, observed_addresses, observed_user, observed_mpp_user, observed_mprv,
                        observed_address, observed_size, observed_store, observed_pc}));
        assert($stable({data_request_bits_address, data_request_bits_data, data_request_bits_write,
                        data_request_bits_machine, data_request_bits_mask, data_request_bits_size,
                        data_request_bits_operation}));
      end
      // END CONTRACT hold
      // BEGIN CONTRACT query
      if (past_valid && !$past(reset) && $stable({observed_configs, observed_addresses, observed_machine,
          observed_address, observed_size, observed_store})) assert($stable(observed_allowed));
      // END CONTRACT query
      // BEGIN CONTRACT busy
      assert(data_busy == (observed_active && observed_sent) && (!data_busy || observed_allowed));
      // END CONTRACT busy
      // BEGIN CONTRACT denial
      assert(!shadow_configured || observed_allowed == interval_permission);
      assert(!data_request_valid || (observed_active && !observed_sent && observed_allowed &&
             data_request_bits_address == observed_address && data_request_bits_size == observed_size &&
             data_request_bits_write == observed_store && data_request_bits_machine == shadow_machine &&
             (!shadow_configured || interval_permission)));
      assert(!shadow_denied || !data_request_valid);
      // END CONTRACT denial
      // BEGIN CONTRACT retention
      if (past_valid && !$past(reset) && $past(data_request_valid && !data_request_ready)) begin
        assert(data_request_valid);
        assert($stable({data_request_bits_address, data_request_bits_data, data_request_bits_write,
                        data_request_bits_machine, data_request_bits_mask, data_request_bits_size,
                        data_request_bits_operation}));
      end
      // END CONTRACT retention
`endif
`ifdef REACHABILITY
      if (observed_csr_write) begin
        assert(retire_valid && !retire_trap && observed_csr_address == retire_word[31:20]);
        case (retire_pc)
          4: assert(observed_csr_address == 12'h305 && observed_csr_data == 128);
          16: assert(observed_csr_address == 12'h3b0 && observed_csr_data == 1024);
          20: assert(observed_csr_address == 12'h3b1 && observed_csr_data == 1024);
          32: assert(observed_csr_address == 12'h3a0 && observed_csr_data == CONFIG);
          40: assert(!MACHINE && observed_csr_address == 12'h300 && observed_csr_data == 0);
          48: assert(!MACHINE && observed_csr_address == 12'h341 && observed_csr_data == 64);
          default: assert(0);
        endcase
      end
      if (retire_valid && retire_pc == 68) assert(shadow_denied);
`endif
    end
  end

  // Entry zero permits [0,4096). Entry one denies [4096,4100).
  function [31:0] rom(input [31:0] address);
    case (address)
      0: rom = 32'h08000093;
      4: rom = 32'h30509073;
      8: rom = 32'h000010b7;
      12: rom = 32'h0020d113;
      16: rom = 32'h3b011073;
      20: rom = 32'h3b111073;
      24: rom = MACHINE ? 32'h00009137 : 32'h00001137;
      28: rom = 32'h00f10113;
      32: rom = 32'h3a011073;
      36: rom = 32'h05a00193;
      40: rom = MACHINE ? 32'h0180006f : 32'h30001073;
      44: rom = 32'h04000113;
      48: rom = 32'h34111073;
      52: rom = 32'h30200073;
      56: rom = 32'h0030a023;
      60: rom = 32'h0030a023;
      64: rom = 32'hffc0a203;
      68: rom = STORE ? 32'h0030a023 : 32'h0000a183;
      72: rom = 32'h0030a423;
      128: rom = 32'h342022f3;
      132: rom = 32'h34102373;
      136: rom = 32'h343023f3;
      140: rom = 32'h00018413;
      144: rom = 32'h300024f3;
      default: rom = 32'h0000006f;
    endcase
  endfunction

  reg instruction_busy = 0, instruction_released = 0;
  reg [31:0] instruction_address = 0;
  reg data_busy = 0, data_released = 0;
`ifdef REPLACE_PEER
  assign instruction_request_ready = (!instruction_busy || instruction_response) && accept_instruction;
  assign data_request_ready = (!data_busy || data_response) && accept_data;
`else
  assign instruction_request_ready = !instruction_busy && accept_instruction;
  assign data_request_ready = !data_busy && accept_data;
`endif
  assign instruction_response_valid = instruction_busy && (instruction_released || release_instruction);
  assign instruction_response_bits_data = rom(instruction_address);
  assign instruction_response_bits_fault = 0;
  assign data_response_valid = data_busy && (data_released || release_data);
  assign data_response_bits_data = 32'h12345678;
  assign data_response_bits_fault = 0;
  wire instruction_request = instruction_request_valid && instruction_request_ready;
  wire instruction_response = instruction_response_valid && instruction_response_ready;
  wire data_request = data_request_valid && data_request_ready;
  wire data_response = data_response_valid && data_response_ready;
  (* keep *) wire forbidden_request = data_request_valid && data_request_bits_address == 4096;

  reg past_valid = 0, saw_allowed = 0, saw_denied = 0, saw_replacement = 0;
  wire finished = retire_valid && retire_pc == 148 && saw_denied;
  reg [4:0] event_index = 0;
  reg [31:0] expected_pc, expected_next, expected_value;
  reg [4:0] expected_rd;
  always @* begin
    expected_pc = event_index < BODY_INDEX ? event_index * 4 :
                  event_index < HANDLER_INDEX ? 64 + (event_index - BODY_INDEX) * 4 :
                  128 + (event_index - HANDLER_INDEX) * 4;
    expected_next = event_index == BODY_INDEX - 1 ? 64 : event_index == BODY_INDEX + 1 ? 128 :
                    event_index == FINAL_INDEX ? 148 : expected_pc + 4;
    expected_rd = 0;
    expected_value = 0;
    case (event_index)
      0: begin expected_rd = 1; expected_value = 128; end
      2: begin expected_rd = 1; expected_value = 4096; end
      3: begin expected_rd = 2; expected_value = 1024; end
      6: begin expected_rd = 2; expected_value = MACHINE ? 32'h9000 : 32'h1000; end
      7: begin expected_rd = 2; expected_value = CONFIG; end
      9: begin expected_rd = 3; expected_value = 90; end
      11: if (!MACHINE) begin expected_rd = 2; expected_value = 64; end
    endcase
    case (event_index)
      BODY_INDEX: begin expected_rd = 4; expected_value = 32'h12345678; end
      HANDLER_INDEX: begin expected_rd = 5; expected_value = CAUSE; end
      HANDLER_INDEX+1: begin expected_rd = 6; expected_value = 68; end
      HANDLER_INDEX+2: begin expected_rd = 7; expected_value = 4096; end
      HANDLER_INDEX+3: begin expected_rd = 8; expected_value = 90; end
      HANDLER_INDEX+4: begin expected_rd = 9; expected_value = MACHINE ? 32'h1800 : 0; end
    endcase
  end

  always @(posedge clock) begin
    past_valid <= 1;
    if (reset) begin
      instruction_busy <= 0;
      instruction_released <= 0;
      data_busy <= 0;
      data_released <= 0;
      event_index <= 0;
      saw_allowed <= 0;
      saw_denied <= 0;
      saw_replacement <= 0;
    end else begin
`ifdef REACHABILITY
      assert(!interrupt_valid && !sleeping);
`endif
`ifndef SHADOW_CONTRACT
      assert(!forbidden_request);
`endif
      if (instruction_response_valid) instruction_released <= 1;
      if (instruction_response) begin
        instruction_busy <= 0;
        instruction_released <= 0;
      end
      if (instruction_request) begin
`ifdef REACHABILITY
        assert(!instruction_busy || instruction_response);
`endif
        instruction_busy <= 1;
        instruction_address <= instruction_request_bits_address;
        instruction_released <= 0;
        if (instruction_response && instruction_address != instruction_request_bits_address) saw_replacement <= 1;
      end
      if (data_request_valid) begin
`ifdef REACHABILITY
        assert(!data_busy && !saw_allowed);
        assert(data_request_bits_address == 4092 && !data_request_bits_write);
        assert(data_request_bits_mask == 0 && data_request_bits_size == 2);
        assert(data_request_bits_operation == 0 && data_request_bits_machine == MACHINE);
`endif
      end
      if (data_response_valid) data_released <= 1;
      if (data_response) begin
`ifdef REACHABILITY
        assert(data_busy);
        assert(retire_valid && !retire_trap && retire_pc == 64);
`endif
        data_busy <= 0;
        data_released <= 0;
      end
      if (data_request) begin
        data_busy <= 1;
        data_released <= 0;
        saw_allowed <= 1;
      end
`ifdef REACHABILITY
      assert(!data_response_ready || data_busy);
`endif
      if (past_valid && !$past(reset)) begin
`ifdef REACHABILITY
        if ($past(instruction_request_valid && !instruction_request_ready)) begin
          assert(instruction_request_valid);
          assert($stable({instruction_request_bits_address, instruction_request_bits_data,
                          instruction_request_bits_write, instruction_request_bits_machine,
                          instruction_request_bits_mask, instruction_request_bits_size,
                          instruction_request_bits_operation}));
        end
`endif
        if ($past(data_request_valid && !data_request_ready)) begin
`ifndef SHADOW_CONTRACT
          assert(data_request_valid);
          assert($stable({data_request_bits_address, data_request_bits_data,
                          data_request_bits_write, data_request_bits_machine,
                          data_request_bits_mask, data_request_bits_size, data_request_bits_operation}));
`endif
        end
      end
      if (retire_valid) begin
`ifdef REACHABILITY
        assert(retire_pc == expected_pc && retire_word == rom(expected_pc));
        assert(retire_nextPc == expected_next);
        assert(retire_userMode == (!MACHINE && (event_index == BODY_INDEX || event_index == BODY_INDEX + 1)));
        assert(retire_trap == (event_index == BODY_INDEX + 1));
        assert(retire_writes == (expected_rd != 0));
        if (retire_writes) assert(retire_rd == expected_rd && retire_value == expected_value);
`endif
`ifndef SHADOW_CONTRACT
        assert(!retire_trap || retire_pc == 68);
`endif
        if (retire_pc == 68) begin
`ifdef REACHABILITY
          assert(saw_allowed && !data_busy && !data_request_valid);
`endif
`ifndef SHADOW_CONTRACT
          assert(retire_trap && retire_cause == CAUSE && retire_tval == 4096);
          assert(retire_nextPc == 128 && !retire_writes && retire_userMode == !MACHINE);
`endif
          saw_denied <= 1;
        end
`ifdef REACHABILITY
        if (retire_pc >= 128 && retire_pc <= 144) begin
          assert(saw_denied && !retire_userMode && !retire_trap && retire_writes);
          case (retire_pc)
            128: assert(retire_rd == 5 && retire_value == CAUSE);
            132: assert(retire_rd == 6 && retire_value == 68);
            136: assert(retire_rd == 7 && retire_value == 4096);
            140: assert(retire_rd == 8 && retire_value == 90);
            144: assert(retire_rd == 9 && retire_value == (MACHINE ? 32'h1800 : 0));
          endcase
        end
`endif
        if (event_index != FINAL_INDEX) event_index <= event_index + 1;
      end
`ifdef REACHABILITY
`ifdef REPLACEMENT_WITNESS
      assert(!(finished && saw_replacement));
`else
      assert(!finished);
`endif
`endif
    end
  end
endmodule
