// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
// These additional payload relationships require a fresh commercial proof.
(* keep *) wire k_guard_07a5 = dut.dm.commandValid &&
    dut.dm.command_register == 16'h07a5;
(* keep *) wire k_guard_07b1 = dut.dm.commandValid &&
    dut.dm.command_register == 16'h07b1;
(* keep *) wire k_guard_1006 = scenario == 2'd1 && dut.dm.commandValid &&
    dut.dm.command_register == 16'h1006;
wire k_complete_extra_payload =
    (!k_guard_07a5 || dut.dm.operands_data == 32'd8) &&
    (!k_guard_07b1 || dut.dm.operands_data == 32'd44) &&
    (!k_guard_1006 || dut.dm.operands_data == 32'd291);
