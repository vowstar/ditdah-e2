// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

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
wire last_resume_cancel_owner = !dut.debug.cancelInjection;
wire last_resume_ok = last_resume_step_domain && last_resume_status_owner &&
    last_resume_response_owner && last_resume_setup_halt && last_resume_entry &&
    last_resume_pending && last_resume_terminal && last_resume_pulse_owner && last_resume_cancel_owner;
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

wire core_cluster_handler = (((scenario == 2'd3 ||
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
         (reset || !initialized || !target_trap || dmi_phase >= execution_phase))) && (scenario != 2'd0 || core_setup_protocol_consistent)) && (scenario != 2'd0 || last_resume_ok) && (scenario != 2'd0 || ((scenario != 2'd0 ||
        (store_phase_configuration && store_first_target_armed &&
         store_retry_trigger_disabled && store_phase_clock_ready)) && handler_first_pending_trap && handler_snapshot && handler_pipeline_owner && handler_r7_owner)) && handler_program_history);
wire core_cluster_retry = (((scenario == 2'd3 ||
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
         (reset || !initialized || !target_trap || dmi_phase >= execution_phase))) && (scenario != 2'd0 || core_setup_protocol_consistent)) && (scenario != 2'd0 || last_resume_ok) && (scenario != 2'd0 ||
        (store_phase_configuration && store_first_target_armed &&
         store_retry_trigger_disabled && store_phase_clock_ready)) && normal_retry_ok);
wire core_cluster_older = reset || !initialized || dmi_phase < execution_phase || core_older_history_ok;
wire core_complete_cluster_consistent = core_cluster_handler && core_cluster_retry && core_cluster_older;
