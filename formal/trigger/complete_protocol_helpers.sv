// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

wire core_ledger_window_0 = ((dmi_phase == 5'd7 && dmi_pending) || dmi_phase == 5'd8 || dmi_phase == 5'd9 || (dmi_phase == 5'd10 && !dmi_pending));
wire core_ledger_window_1 = ((dmi_phase == 5'd10 && dmi_pending) || dmi_phase == 5'd11 || dmi_phase == 5'd12 || (dmi_phase == 5'd13 && !dmi_pending));
wire core_ledger_window_2 = ((dmi_phase == 5'd13 && dmi_pending) || dmi_phase == 5'd14 || dmi_phase == 5'd15 || (dmi_phase == 5'd16 && !dmi_pending));
wire core_ledger_window_3 = ((dmi_phase == 5'd16 && dmi_pending) || dmi_phase == 5'd17 || dmi_phase == 5'd18 || (dmi_phase == 5'd19 && !dmi_pending));
wire core_ledger_window_4 = ((dmi_phase == 5'd19 && dmi_pending) || dmi_phase == 5'd20 || dmi_phase == 5'd21 || dmi_phase == 5'd22);
wire core_setup_phase_command_ledger = (reset || !initialized || dut.dm.error != 3'd0 || ((!core_ledger_window_0 || (dut.dm.commandValid && dut.dm.command_register == 16'h07a2)) && (!core_ledger_window_1 || (dut.dm.commandValid && dut.dm.command_register == 16'h07a1)) && (!core_ledger_window_2 || (dut.dm.commandValid && dut.dm.command_register == 16'h07a5)) && (!core_ledger_window_3 || (dut.dm.commandValid && dut.dm.command_register == 16'h0305)) && (!core_ledger_window_4 || (dut.dm.commandValid && dut.dm.command_register == 16'h07b1))));

wire core_setup_halt_phase = (reset || !initialized || !dut.dm.resume || dmi_phase >= execution_phase) && (reset || !initialized || dmi_phase != 5'd2 || !dmi_pending || dmi_response_bits_data[9:8] != 2'd3 || dut.debug.halted) && (reset || !initialized || dmi_phase < 5'd3 || dmi_phase >= execution_phase || dut.debug.halted);
wire core_setup_poll_coherent = (reset || !initialized || !dmi_pending || (dmi_phase != 5'd4 && dmi_phase != 5'd5 && dmi_phase != 5'd8 && dmi_phase != 5'd11 && dmi_phase != 5'd14 && dmi_phase != 5'd17 && dmi_phase != 5'd20 && dmi_phase != 5'd23) || dmi_response_bits_data[12] || dmi_response_bits_data[10:8] != 3'd0 || (!dut.dm.busy && dut.dm.error == 3'd0));

wire core_setup_lifecycle_done_0 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h07a2 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || (dut.csr.trigger.address_0 == 32'd48));
wire core_setup_lifecycle_done_1 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h07a1 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || ((dut.csr.trigger.machine && dut.csr.trigger.execute)));
wire core_setup_lifecycle_done_2 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h07a5 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || (dut.csr.trigger.mte));
wire core_setup_lifecycle_done_3 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h0305 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || (dut.csr.mtvec == 32'd56));
wire core_setup_lifecycle_done_4 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h07b1 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || (dut._debug_core_resumePc == 32'd44));
wire core_setup_lifecycle_history_0 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || dmi_phase < 5'd9 || (dut.csr.trigger.address_0 == 32'd48));
wire core_setup_lifecycle_history_1 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || dmi_phase < 5'd12 || ((dut.csr.trigger.machine && dut.csr.trigger.execute)));
wire core_setup_lifecycle_history_2 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || dmi_phase < 5'd15 || (dut.csr.trigger.mte));
wire core_setup_lifecycle_history_3 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || dmi_phase < 5'd18 || (dut.csr.mtvec == 32'd56));
wire core_setup_lifecycle_error_busy_owner = (reset || !initialized || (dut.dm.error == 3'd0 && (!dut.dm.busy || ((dmi_phase == 5'd7 && dmi_pending) || dmi_phase == 5'd8 || (dmi_phase == 5'd10 && dmi_pending) || dmi_phase == 5'd11 || (dmi_phase == 5'd13 && dmi_pending) || dmi_phase == 5'd14 || (dmi_phase == 5'd16 && dmi_pending) || dmi_phase == 5'd17 || (dmi_phase == 5'd19 && dmi_pending) || dmi_phase == 5'd20))));
wire core_setup_lifecycle_parent_ok = core_setup_lifecycle_done_0 && core_setup_lifecycle_done_1 && core_setup_lifecycle_done_2 && core_setup_lifecycle_done_3 && core_setup_lifecycle_done_4 && core_setup_lifecycle_history_0 && core_setup_lifecycle_history_1 && core_setup_lifecycle_history_2 && core_setup_lifecycle_history_3 && core_setup_lifecycle_error_busy_owner;
wire core_setup_lifecycle_cache_lifetime = (reset || !initialized || !dut.dm.commandValid || dmi_phase >= 5'd7);
wire core_setup_lifecycle_response_class = (reset || !initialized || !dut.debug.responding || dut.debug.response_error == 3'd0);
wire core_setup_lifecycle_halted_owner = (!dut.debug.halted || (!dut.xValid && (!dut.mValid || dut.m_trap)));
wire core_setup_lifecycle_setup_pipeline_empty = (reset || !initialized || dmi_phase < 5'd3 || dmi_phase >= execution_phase || (!dut.xValid && !dut.mValid));
wire core_setup_lifecycle_ok = core_setup_lifecycle_parent_ok && core_setup_lifecycle_cache_lifetime && core_setup_lifecycle_response_class && core_setup_lifecycle_halted_owner && core_setup_lifecycle_setup_pipeline_empty;

wire core_pre_target_configuration = (reset || !initialized || dmi_phase < execution_phase || target_trap || dut.csr.trigger.address_0 == 32'd48);
wire core_pre_target_dpc_owner = (reset || !initialized || dmi_phase < execution_phase || target_trap || dut._debug_core_resumePc <= 32'd52);
wire core_pre_target_architectural_owner = (reset || !initialized || dmi_phase < execution_phase || target_trap || dut.debug.halted || dut.architecturalPc <= 32'd52);
wire core_pre_target_x_owner = (reset || !initialized || dmi_phase < execution_phase || target_trap || !dut.xValid || dut.x_pc <= 32'd52);
wire core_pre_target_m_owner = (reset || !initialized || dmi_phase < execution_phase || target_trap || !dut.mValid || dut.m_instruction_pc <= 32'd52);
wire core_pre_target_trap_owner = (reset || !initialized || dmi_phase < execution_phase || target_trap || !dut.mValid || !dut.m_trap || (dut.m_instruction_pc == 32'd48 && dut.m_cause == 32'd3 && dut.m_tval == 32'd48));
wire core_pre_target_stopped_break_owner = (reset || !initialized || dmi_phase < execution_phase || target_trap || dut.debug.halted || !dut.debug.stopping || dut.debug.stopCause != 3'd1 || dut.debug.breakPc <= 32'd52);
wire core_pre_target_ok = core_pre_target_configuration && core_pre_target_dpc_owner && core_pre_target_architectural_owner && core_pre_target_x_owner && core_pre_target_m_owner && core_pre_target_trap_owner && core_pre_target_stopped_break_owner;
wire core_post_target_dpc_owner = (reset || !initialized || dmi_phase < execution_phase || !target_trap || !dut.csr.trigger.machine || dut._debug_core_resumePc <= 32'd96);
wire core_post_target_architectural_owner = (reset || !initialized || dmi_phase < execution_phase || !target_trap || !dut.csr.trigger.machine || dut.debug.halted || dut.architecturalPc <= 32'd96);
wire core_post_target_m_owner = (reset || !initialized || dmi_phase < execution_phase || !target_trap || !dut.csr.trigger.machine || !dut.mValid || dut.m_instruction_pc <= 32'd96);
wire core_post_target_x_owner = (reset || !initialized || dmi_phase < execution_phase || !target_trap || !dut.csr.trigger.machine || !dut.xValid || (dut.x_pc <= 32'd100 && (dut.x_pc <= 32'd96 || (dut.mValid && dut.m_instruction_pc == 32'd96 && !dut.m_trap))));
wire core_post_target_stopped_break_owner = (reset || !initialized || dmi_phase < execution_phase || !target_trap || !dut.csr.trigger.machine || dut.debug.halted || !dut.debug.stopping || dut.debug.stopCause != 3'd1 || dut.debug.breakPc <= 32'd96);
wire core_post_target_ok = core_post_target_dpc_owner && core_post_target_architectural_owner && core_post_target_m_owner && core_post_target_x_owner && core_post_target_stopped_break_owner;

wire core_setup_protocol_consistent =
    (core_setup_phase_command_ledger && core_setup_halt_phase &&
     core_setup_poll_coherent && core_setup_lifecycle_ok &&
     core_pre_target_ok && core_post_target_ok);
