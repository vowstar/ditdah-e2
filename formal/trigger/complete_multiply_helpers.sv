// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

wire core_ledger_window_0 = ((dmi_phase == 5'd7 && dmi_pending) || dmi_phase == 5'd8 || dmi_phase == 5'd9 || (dmi_phase == 5'd10 && !dmi_pending));
wire core_ledger_window_1 = ((dmi_phase == 5'd10 && dmi_pending) || dmi_phase == 5'd11 || dmi_phase == 5'd12 || (dmi_phase == 5'd13 && !dmi_pending));
wire core_ledger_window_2 = ((dmi_phase == 5'd13 && dmi_pending) || dmi_phase == 5'd14 || dmi_phase == 5'd15 || (dmi_phase == 5'd16 && !dmi_pending));
wire core_ledger_window_3 = ((dmi_phase == 5'd16 && dmi_pending) || dmi_phase == 5'd17 || dmi_phase == 5'd18 || (dmi_phase == 5'd19 && !dmi_pending));
wire core_ledger_window_4 = ((dmi_phase == 5'd19 && dmi_pending) || dmi_phase == 5'd20 || dmi_phase == 5'd21 || (dmi_phase == 5'd22 && !dmi_pending));
wire core_ledger_window_5 = ((dmi_phase == 5'd22 && dmi_pending) || dmi_phase == 5'd23 || dmi_phase == 5'd24 || dmi_phase == 5'd25);
wire core_setup_phase_command_ledger = (reset || !initialized || dut.dm.error != 3'd0 || ((!core_ledger_window_0 || (dut.dm.commandValid && dut.dm.command_register == 16'h07a2)) && (!core_ledger_window_1 || (dut.dm.commandValid && dut.dm.command_register == 16'h07a1)) && (!core_ledger_window_2 || (dut.dm.commandValid && dut.dm.command_register == 16'h07a5)) && (!core_ledger_window_3 || (dut.dm.commandValid && dut.dm.command_register == 16'h1006)) && (!core_ledger_window_4 || (dut.dm.commandValid && dut.dm.command_register == 16'h0305)) && (!core_ledger_window_5 || (dut.dm.commandValid && dut.dm.command_register == 16'h07b1))));
wire core_setup_halt_phase = (reset || !initialized || !dut.dm.resume || dmi_phase >= execution_phase) && (reset || !initialized || dmi_phase != 5'd2 || !dmi_pending || dmi_response_bits_data[9:8] != 2'd3 || dut.debug.halted) && (reset || !initialized || dmi_phase < 5'd3 || dmi_phase >= execution_phase || dut.debug.halted);
wire core_setup_poll_coherent = (reset || !initialized || !dmi_pending || (dmi_phase != 5'd4 && dmi_phase != 5'd5 && dmi_phase != 5'd8 && dmi_phase != 5'd11 && dmi_phase != 5'd14 && dmi_phase != 5'd17 && dmi_phase != 5'd20 && dmi_phase != 5'd23) || dmi_response_bits_data[12] || dmi_response_bits_data[10:8] != 3'd0 || (!dut.dm.busy && dut.dm.error == 3'd0));
wire core_setup_lifecycle_done_0 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h07a2 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || (dut.csr.trigger.address_0 == 32'd48));
wire core_setup_lifecycle_done_1 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h07a1 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || (dut.csr.trigger.machine && dut.csr.trigger.execute));
wire core_setup_lifecycle_done_2 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h07a5 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || (dut.csr.trigger.mte));
wire core_setup_lifecycle_done_3 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h1006 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || (dut.registers_4 == 32'd291));
wire core_setup_lifecycle_done_4 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h0305 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || (dut.csr.mtvec == 32'd56));
wire core_setup_lifecycle_done_5 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || !(dut.dm.commandValid && dut.dm.command_register == 16'h07b1 && (!dut.dm.busy || (dut.dm.issued && dut.debug.responding && dut.debug.response_error == 3'd0))) || (dut._debug_core_resumePc == 32'd44));
wire core_setup_lifecycle_history_0 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || dmi_phase < 5'd9 || (dut.csr.trigger.address_0 == 32'd48));
wire core_setup_lifecycle_history_1 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || dmi_phase < 5'd12 || (dut.csr.trigger.machine && dut.csr.trigger.execute));
wire core_setup_lifecycle_history_2 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || dmi_phase < 5'd15 || (dut.csr.trigger.mte));
wire core_setup_lifecycle_history_3 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || dmi_phase < 5'd18 || (dut.registers_4 == 32'd291));
wire core_setup_lifecycle_history_4 = (reset || !initialized || dmi_phase >= execution_phase || dut.dm.error != 3'd0 || dmi_phase < 5'd21 || (dut.csr.mtvec == 32'd56));
wire core_setup_lifecycle_error_busy_owner = (reset || !initialized || (dut.dm.error == 3'd0 && (!dut.dm.busy || ((dmi_phase == 5'd7 && dmi_pending) || dmi_phase == 5'd8 || (dmi_phase == 5'd10 && dmi_pending) || dmi_phase == 5'd11 || (dmi_phase == 5'd13 && dmi_pending) || dmi_phase == 5'd14 || (dmi_phase == 5'd16 && dmi_pending) || dmi_phase == 5'd17 || (dmi_phase == 5'd19 && dmi_pending) || dmi_phase == 5'd20 || (dmi_phase == 5'd22 && dmi_pending) || dmi_phase == 5'd23))));
wire core_setup_r6_postsetup = (reset || !initialized || dmi_phase < 5'd18 || dut.registers_4 == 32'd291);
wire core_setup_lifecycle_parent_ok = core_setup_lifecycle_done_0 && core_setup_lifecycle_done_1 && core_setup_lifecycle_done_2 && core_setup_lifecycle_done_3 && core_setup_lifecycle_done_4 && core_setup_lifecycle_done_5 && core_setup_lifecycle_history_0 && core_setup_lifecycle_history_1 && core_setup_lifecycle_history_2 && core_setup_lifecycle_history_3 && core_setup_lifecycle_history_4 && core_setup_lifecycle_error_busy_owner && core_setup_r6_postsetup;
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
wire last_resume_operating = !reset && initialized;
wire last_resume_step_domain = !dut.debug.step && !dut.debug.stepping;
wire last_resume_status_owner = (!dut.debug.resumeAck || !dut.debug.halted) &&
    (!dut.debug.halted || !dut.debug.stopping);
wire last_resume_response_owner = !dut.debug.responding ||
    (dut.dm.active && dut.dm.busy && dut.dm.needsHart && dut.dm.issued);
wire last_resume_setup_halt = !last_resume_operating ||
    !((dmi_phase == 5'd1 && dmi_pending) ||
      (dmi_phase >= 5'd2 && dmi_phase < execution_phase)) ||
    (dut.dm.halt && !dut.dm.resume);
wire last_resume_entry = !last_resume_operating ||
    dmi_phase != execution_phase || dmi_pending ||
    (dut.dm.halt && !dut.dm.resume && dut.debug.halted &&
     !dut.xValid && !dut.mValid && !dut.debug.responding &&
     !dut.debug.resumeAck && !target_trap);
wire last_resume_pending = !last_resume_operating ||
    dmi_phase != execution_phase || !dmi_pending ||
    (!dut.dm.halt && dut.dm.resume && dut.debug.halted &&
     !dut.xValid && !dut.mValid && !dut.debug.responding &&
     !dut.debug.resumeAck && !target_trap);
wire last_resume_terminal = !last_resume_operating || dmi_phase <= execution_phase ||
    (!dut.dm.halt && !dut._debug_core_resume &&
     (!dut.dm.resume || (dut.debug.resumeAck && !dut.debug.halted)));
wire last_resume_pulse_owner = !last_resume_operating || !dut._debug_core_resume ||
    (dmi_phase == execution_phase && dmi_pending && !target_trap &&
     dut.debug.halted && !dut.xValid && !dut.mValid);
wire last_resume_ok = last_resume_step_domain && last_resume_status_owner &&
    last_resume_response_owner && last_resume_setup_halt && last_resume_entry &&
    last_resume_pending && last_resume_terminal && last_resume_pulse_owner;
wire handler_postexec = check && dmi_phase >= execution_phase;
wire handler_first_pending_trap = !(handler_postexec && dut.mValid && dut.m_trap) ||
    (!target_trap && dut.m_instruction_pc == 32'd48 && dut.m_cause == 32'd3 &&
     dut.m_tval == 32'd48 && dut.csr.trigger.hit);
wire handler_snapshot = !(handler_postexec && target_trap && dut.csr.trigger.machine) ||
    (dut.csr.mepc == 32'd48 && dut.csr.mcause == 32'd3 && dut.csr.mtval == 32'd48 &&
     dut.csr.trigger.hit && dut.csr.trigger.mpte && !dut.csr.trigger.mte);
wire handler_pipeline_owner = !(handler_postexec && target_trap &&
    ((dut.mValid && dut.m_instruction_pc >= 32'd56 && dut.m_instruction_pc <= 32'd92) ||
     (dut.xValid && dut.x_pc >= 32'd56 && dut.x_pc <= 32'd92) ||
     (!dut.debug.halted && dut.architecturalPc >= 32'd56 && dut.architecturalPc <= 32'd96))) ||
    dut.csr.trigger.machine;
wire handler_r7_epc = !(handler_postexec && target_trap &&
    (dut.architecturalPc == 32'd60 || dut.architecturalPc == 32'd64)) ||
    dut.registers_5 == dut.csr.mepc;
wire handler_r7_cause = !(handler_postexec && target_trap &&
    (dut.architecturalPc == 32'd68 || dut.architecturalPc == 32'd72)) ||
    dut.registers_5 == dut.csr.mcause;
wire handler_r7_tval = !(handler_postexec && target_trap &&
    (dut.architecturalPc == 32'd76 || dut.architecturalPc == 32'd80)) ||
    dut.registers_5 == dut.csr.mtval;
wire handler_r7_control = !(handler_postexec && target_trap &&
    (dut.architecturalPc == 32'd84 || dut.architecturalPc == 32'd88)) ||
    dut.registers_5 == 32'h00000080;
wire handler_r7_hit = !(handler_postexec && target_trap &&
    (dut.architecturalPc == 32'd92 || dut.architecturalPc == 32'd96)) ||
    dut.registers_5 == 32'h20100044;
wire handler_r7_owner = handler_r7_epc && handler_r7_cause && handler_r7_tval &&
    handler_r7_control && handler_r7_hit;
wire handler_after_target = handler_postexec && target_trap;
wire handler_mret_forward_metadata = !dut.mValid || dut.m_instruction_word != 32'h30200073 ||
    (dut.m_mret && !dut.m_csr && !dut.m_load && !dut.m_store && !dut.m_wfi &&
     !dut.m_fenceI && !dut.m_writes && dut.m_nextPc == dut.m_instruction_pc + 32'd4);
wire handler_retained_epc = !handler_after_target ||
    (dut.csr.mepc == 32'd48 && dut.csr.trigger.mpte);
wire handler_r7_return_epc = !(handler_after_target &&
    (dut.architecturalPc == 32'd104 || dut.architecturalPc == 32'd108)) ||
    dut.registers_5 == dut.csr.mepc;
wire handler_enabled_pc_history = !handler_after_target || !dut.csr.trigger.machine ||
    (!dut.csr.trigger.mte && (dut.debug.halted || (dut.architecturalPc == 32'd56 || dut.architecturalPc == 32'd60 || dut.architecturalPc == 32'd64 || dut.architecturalPc == 32'd68 || dut.architecturalPc == 32'd72 || dut.architecturalPc == 32'd76 || dut.architecturalPc == 32'd80 || dut.architecturalPc == 32'd84 || dut.architecturalPc == 32'd88 || dut.architecturalPc == 32'd92 || dut.architecturalPc == 32'd96)) &&
     (!dut.mValid || (dut.m_instruction_pc == 32'd56 || dut.m_instruction_pc == 32'd60 || dut.m_instruction_pc == 32'd64 || dut.m_instruction_pc == 32'd68 || dut.m_instruction_pc == 32'd72 || dut.m_instruction_pc == 32'd76 || dut.m_instruction_pc == 32'd80 || dut.m_instruction_pc == 32'd84 || dut.m_instruction_pc == 32'd88 || dut.m_instruction_pc == 32'd92 || dut.m_instruction_pc == 32'd96)) &&
     (!dut.xValid || (dut.x_pc == 32'd56 || dut.x_pc == 32'd60 || dut.x_pc == 32'd64 || dut.x_pc == 32'd68 || dut.x_pc == 32'd72 || dut.x_pc == 32'd76 || dut.x_pc == 32'd80 || dut.x_pc == 32'd84 || dut.x_pc == 32'd88 || dut.x_pc == 32'd92 || dut.x_pc == 32'd96) || (dut.x_pc == 32'd100 && dut.mValid && dut.m_instruction_pc == 32'd96 && !dut.m_trap)));
wire handler_pre_return_pc_history = !handler_after_target || dut.csr.trigger.machine || dut.csr.trigger.mte ||
    ((dut.debug.halted || (dut.architecturalPc == 32'd100 || dut.architecturalPc == 32'd104 || dut.architecturalPc == 32'd108)) &&
     (!dut.mValid || (dut.m_instruction_pc == 32'd100 || dut.m_instruction_pc == 32'd104 || dut.m_instruction_pc == 32'd108)) &&
     (!dut.xValid || (dut.x_pc == 32'd100 || dut.x_pc == 32'd104 || dut.x_pc == 32'd108) || (dut.x_pc == 32'd112 && dut.mValid && dut.m_instruction_pc == 32'd108 && dut.m_mret && !dut.m_trap)));
wire handler_returned_pc_history = !handler_after_target || dut.csr.trigger.machine || !dut.csr.trigger.mte ||
    ((dut.debug.halted || (dut.architecturalPc == 32'd48 || dut.architecturalPc == 32'd52)) &&
     (!dut.mValid || (dut.m_instruction_pc == 32'd48 || dut.m_instruction_pc == 32'd52)) &&
     (!dut.xValid || (dut.x_pc == 32'd48 || dut.x_pc == 32'd52)));
wire handler_program_history = handler_mret_forward_metadata && handler_retained_epc &&
    handler_r7_return_epc && handler_enabled_pc_history && handler_pre_return_pc_history && handler_returned_pc_history;
wire normal_retry_outside = reset || !initialized || dmi_phase < execution_phase || !target_normal;
wire normal_retry_flags = normal_retry_outside || target_trap;
wire normal_retry_m = normal_retry_outside || !dut.mValid ||
    (dut.m_instruction_pc == 32'd52 && !dut.m_trap);
wire normal_retry_x = normal_retry_outside || !dut.xValid || dut.x_pc == 32'd52;
wire normal_retry_arch = normal_retry_outside || dut.debug.halted || dut.architecturalPc == 32'd52;
wire normal_retry_ok = normal_retry_flags && normal_retry_m && normal_retry_x && normal_retry_arch;
wire core_older_history_flag_history = (older_seen || !target_trap);
wire core_older_history_dpc_owner = (reset || !initialized || dmi_phase < execution_phase || older_seen || dut._debug_core_resumePc <= 32'd44);
wire core_older_history_architectural_owner = (reset || !initialized || dmi_phase < execution_phase || older_seen || dut.debug.halted || dut.architecturalPc <= 32'd44);
wire core_older_history_m_owner = (reset || !initialized || dmi_phase < execution_phase || older_seen || !dut.mValid || dut.m_instruction_pc <= 32'd44);
wire core_older_history_x_owner = (reset || !initialized || dmi_phase < execution_phase || older_seen || !dut.xValid || (dut.x_pc <= 32'd48 && (dut.x_pc <= 32'd44 || (dut.mValid && dut.m_instruction_pc == 32'd44))));
wire core_older_history_stopped_break_owner = (reset || !initialized || dmi_phase < execution_phase || older_seen || dut.debug.halted || !dut.debug.stopping || dut.debug.stopCause != 3'd1 || dut.debug.breakPc <= 32'd44);
wire core_older_history_ok = core_older_history_flag_history && core_older_history_dpc_owner && core_older_history_architectural_owner && core_older_history_m_owner && core_older_history_x_owner && core_older_history_stopped_break_owner;

wire core_complete_multiply_consistent = scenario != 2'd1 || ((scenario != 2'd1 || ((scenario == 2'd3 ||
        (core_target_breakpoint_has_armed_owner &&
         (scenario != 2'd1 || core_multiply_trap_metadata_consistent) &&
         core_setup_counter_owner &&
         (!dut.xValid || dut.x_pc[1:0] == 2'b00) &&
         (!dut.mValid || dut.m_instruction_pc[1:0] == 2'b00) &&
         dut.architecturalPc[1:0] == 2'b00 &&
         dut._debug_core_resumePc[1:0] == 2'b00 &&
         dut.csr.mepc[1:0] == 2'b00 &&
         (!(dut.debug.stopping && dut.debug.stopCause == 3'd1) ||
         dut.debug.breakPc[1:0] == 2'b00) &&
         (reset || !initialized ||
          ((!(dmi_pending || dmi_phase != 5'd0) ||
            (past_valid && !past_reset && !systemReset)) &&
           (dmi_pending == dut.dm.responding))) &&
         (!dut.dm.busy || dut.dm.needsHart) &&
         (reset || !initialized || (dmi_phase == 5'd0 && !dmi_pending) ||
          dut.dm.active) &&
         (reset || !initialized || !target_trap || dmi_phase >= execution_phase))) && core_setup_protocol_consistent && (!program_selected_scene ||
        (program_phase_configuration && program_first_target_armed &&
         program_retry_trigger_disabled && program_phase_clock_ready)))) && (last_resume_ok) && (handler_first_pending_trap && handler_snapshot && handler_pipeline_owner && handler_r7_owner) && (handler_program_history) && (normal_retry_ok) && (reset || !initialized || dmi_phase < execution_phase || core_older_history_ok));
