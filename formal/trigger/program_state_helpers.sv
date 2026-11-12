// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire store_csr_fields = !(dut.mValid && dut.m_csr) ||
      (dut.m_csrAddress == dut.m_instruction_word[31:20] &&
       dut.m_csrOperation == dut.m_instruction_word[13:12] &&
       dut.m_csrWrite == (dut.m_instruction_word[13:12] == 2'd1 ||
                         dut.m_instruction_word[19:15] != 5'd0));
  wire store_csr_zero = !(dut.mValid && dut.m_csr &&
      dut.m_instruction_word[19:15] == 5'd0) || dut.m_csrOperand == 32'd0;
  wire store_trigger_addresses =
      (dut.csr.trigger.address_0 == 32'd0 || dut.csr.trigger.address_0 == 32'd48) &&
      (dut.csr.trigger.address_1 == 32'd0 || dut.csr.trigger.address_1 == 32'd48);
  wire store_trigger_controls = !dut.csr.trigger.selected &&
      dut.csr.trigger.machine == dut.csr.trigger.execute &&
      !dut.csr.trigger.dmode && !dut.csr.trigger.debugAction && !dut.csr.trigger.user &&
      !dut.csr.trigger.dmode_0 && !dut.csr.trigger.debugAction_0 &&
      !dut.csr.trigger.user_0 && !dut.csr.trigger.machine_0 && !dut.csr.trigger.execute_0;
  wire store_native_trap_pc = !(dut.mValid && dut.m_trap && dut.m_cause == 32'd3) ||
      dut.m_instruction_pc == 32'd0 || dut.m_instruction_pc == 32'd48;
  wire store_gpr1_value = dut.registers == 32'd0 || dut.registers == 32'd256;
  wire store_mtvec_value = dut.csr.mtvec == 32'd0 || dut.csr.mtvec == 32'd56;
  wire store_debug_memory_idle = !dut.debug.sending && !dut.debug.waiting;
  wire store_generic_state = store_csr_fields && store_csr_zero &&
      store_trigger_addresses && store_trigger_controls && store_native_trap_pc &&
      store_gpr1_value && store_mtvec_value;
  always @(posedge clock) begin
    core_store_source_state: assert(store_generic_state && store_debug_memory_idle);
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire core_armed_target_m_trap =
      !(dut.mValid && dut.m_instruction_pc == 32'd48 &&
        dut.csr.trigger.machine && dut.csr.trigger.execute &&
        dut.csr.trigger.mte && dut.csr.trigger.address_0 == 32'd48) ||
      (dut.m_trap && dut.m_cause == 32'd3 && dut.m_tval == 32'd48);
  always @(posedge clock) begin
    core_armed_target_capture: assert(core_armed_target_m_trap);
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire store_value_csr_word = dut.m_instruction_word[6:0] == 7'h73 &&
      dut.m_instruction_word[13:12] != 2'd0;
  wire store_value_csr_decode = !(dut.mValid && store_value_csr_word) ||
      (dut.m_csr && dut.m_writes && !dut.m_load && !dut.m_store &&
       !dut.m_mret && !dut.m_wfi && !dut.m_fenceI);
  wire store_value_memory_operand =
      !(dut.mValid && dut.m_store && dut.m_instruction_word[24:20] == 5'd7) ||
      dut.m_storeData == dut.registers_5;
  wire store_value_csr_operand =
      !(dut.mValid && dut.m_csr && dut.m_instruction_word[19:15] == 5'd7 &&
        !dut.m_instruction_word[14]) || dut.m_csrOperand == dut.registers_5;
  wire store_value_legal_word = dut.m_instruction_word == 32'h00000013 ||
      dut.m_instruction_word == 32'h30200073 || store_value_csr_word ||
      (dut.m_instruction_word == 32'h0000006f && dut.m_instruction_pc[1:0] == 0);
  wire store_value_trap_class = !(dut.mValid && store_value_legal_word && dut.m_trap) ||
      (dut.m_cause == 32'd3 && dut.m_tval == dut.m_instruction_pc);
  wire store_value_reset_control = !dut.dm.ndmreset &&
      !dut.debug.resetPending && !dut.debug.resetting;
  wire store_value_memory_quiet = !dut.debug.sending && !dut.debug.waiting;
  wire store_value_pending_owner = !data_busy ||
      (dut.sent && dut.mValid && (dut.m_load || dut.m_store) && !dut.m_trap &&
       data_address == dut.m_address && data_write == dut.m_store &&
       (!data_write || (data_write_data == dut.m_storeData && data_write_mask == 4'hf)));
  wire store_value_state = store_value_csr_decode && store_value_memory_operand &&
      store_value_csr_operand && store_value_trap_class && store_value_reset_control &&
      store_value_memory_quiet && (reset || !initialized || store_value_pending_owner);
  always @(posedge clock) begin
    core_store_value_owner_metadata: assert(store_value_state);
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
// This read-only candidate requires a fresh commercial proof.
wire program_selected_scene = scenario == 2'd1 || scenario == 2'd2;
wire [4:0] program_configuration_phase = scenario == 2'd1 ? 5'd21 : 5'd18;
wire program_phase_configuration = !check || dmi_phase < program_configuration_phase ||
    (dut.csr.mtvec == 32'd56 && dut.csr.trigger.address_0 == 32'd48);
wire program_first_target_armed = !check || dmi_phase < execution_phase ||
    target_trap || (dut.csr.mtvec == 32'd56 &&
    dut.csr.trigger.address_0 == 32'd48 && dut.csr.trigger.machine &&
    dut.csr.trigger.execute && dut.csr.trigger.mte);
wire program_retry_trigger_disabled = !check || dmi_phase < execution_phase ||
    !target_trap || !dut.csr.trigger.machine || !dut.csr.trigger.mte;
wire program_phase_clock_ready = reset || !initialized || systemReset ||
    dmi_phase == 5'd0 || (past_valid && !past_reset);
always @(posedge clock) begin
    core_program_configuration_history: assert (!program_selected_scene ||
        (program_phase_configuration && program_first_target_armed &&
         program_retry_trigger_disabled && program_phase_clock_ready));
end
