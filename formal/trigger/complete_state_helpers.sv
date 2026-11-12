// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire core_target_breakpoint_has_armed_owner =
      !(dut.mValid && dut.m_instruction_pc == 32'd48 && dut.m_trap &&
        dut.m_cause == 32'd3) ||
      (dut.csr.trigger.machine && dut.csr.trigger.execute && dut.csr.trigger.mte &&
       dut.csr.trigger.address_0 == 32'd48);
// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire core_multiply_trap_metadata_consistent =
      !(dut.mValid && dut.m_instruction_word == 32'h026282b3 && dut.m_trap) ||
      (dut.m_cause == 32'd3 && dut.m_tval == dut.m_instruction_pc);
// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire [4:0] core_setup_terminal_phase = execution_phase + 5'd1;
  wire core_setup_counter_owner = reset || !initialized ||
      (dmi_phase <= core_setup_terminal_phase &&
       (dmi_phase != core_setup_terminal_phase || !dmi_pending));
  always @(posedge clock) begin
    core_complete_target_trap_metadata: assert(scenario == 2'd3 ||
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
         (reset || !initialized || !target_trap || dmi_phase >= execution_phase)));
  end
