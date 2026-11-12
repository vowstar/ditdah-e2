// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire k_data0_domain = dut.dm.data0 == 32'd0 || dut.dm.data0 == 32'd12 ||
      dut.dm.data0 == 32'h20000044 || dut.dm.data0 == 32'd8 || dut.dm.data0 == 32'd256;
  wire k_operand_domain = dut.dm.operands_data == 32'd0 || dut.dm.operands_data == 32'd12 ||
      dut.dm.operands_data == 32'h20000044 || dut.dm.operands_data == 32'd8 ||
      dut.dm.operands_data == 32'd256;
  wire k_command_format = !dut.dm.command_memory && dut.dm.command_write &&
      dut.dm.command_size == 2'd2 && dut.dm.command_transfer && !dut.dm.command_postIncrement && !dut.dm.command_postExec;
  (* keep *) wire k_observe_command_valid = dut.dm.commandValid;
  (* keep *) wire [15:0] k_observe_command_register = dut.dm.command_register;
  (* keep *) wire [31:0] k_observe_operand = dut.dm.operands_data;
  (* keep *) wire k_guard_07a2 = dut.dm.commandValid && dut.dm.command_register == 16'h07a2;
  (* keep *) wire k_guard_07a1 = dut.dm.commandValid && dut.dm.command_register == 16'h07a1;
  (* keep *) wire k_guard_0305 = dut.dm.commandValid && dut.dm.command_register == 16'h0305;
  always @(posedge clock) begin
    core_setup_transaction_payload_metadata: assert(
        (!dmi_response_valid || dmi_pending) &&
        (!dut.dm.busy || dut.dm.commandValid) &&
        (!dut.dm.commandValid || k_command_format) &&
        (!dut.dm.active || k_data0_domain) &&
        (!dut.dm.commandValid || k_operand_domain) &&
        (!dut.dm.active || dut.dm.auto == 18'd0));
    core_setup_exact_command_payload: assert(
        (!k_guard_07a2 || dut.dm.operands_data == 32'd12) &&
        (!k_guard_07a1 || dut.dm.operands_data == 32'h20000044) &&
        (!k_guard_0305 || dut.dm.operands_data == 32'd256));
    cover_setup_guard_07a2: cover(k_guard_07a2);
    cover_setup_guard_07a1: cover(k_guard_07a1);
    cover_setup_guard_0305: cover(k_guard_0305);
  end
