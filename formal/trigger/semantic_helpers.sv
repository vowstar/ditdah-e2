// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire [31:0] core_flow_m_continuation = dut.m_trap ?
      dut.m_instruction_pc + 32'd4 : dut.m_nextPc;
  wire [31:0] core_flow_frontier = dut.fetch.buffered ?
      dut.fetch.packet_pc : dut.fetch.assemblyPc;
  wire [31:0] core_flow_expected_frontier = dut.xValid ? dut.x_pc + 32'd4 :
      dut.mValid ? core_flow_m_continuation : dut.architecturalPc;
  always @(posedge clock) begin
    core_native_pipeline_pc_owner: assert(
        (!dut.mValid || dut.m_instruction_pc == dut.architecturalPc) &&
        (!dut.xValid || dut.x_pc == (dut.mValid ? core_flow_m_continuation : dut.architecturalPc)) &&
        (!core_geom_sync_epoch || core_flow_frontier == core_flow_expected_frontier) &&
        (!(core_geom_sync_epoch && dut.fetch.buffered) || dut.fetch.assemblyPc == dut.fetch.packet_pc + 32'd4) &&
        (!(dut.mValid && dut.m_debugBreak) || dut.m_instruction_word == 32'h00100073));
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
// Review fragments only; writes is decode intent, not an architectural write event.
  wire core_sequential_addi_metadata_A = !dut.mValid ||
      dut.m_instruction_word != 32'h10000093 ||
      (dut.m_writes && dut.m_rd == 5'd1 && dut.m_value == 32'd256 &&
       dut.m_nextPc == dut.m_instruction_pc + 32'd4);
  wire core_mtvec_write_metadata_C = !dut.mValid ||
      dut.m_instruction_word != 32'h30509073 ||
      (dut.m_csr && dut.m_csrWrite && dut.m_writes &&
       dut.m_csrAddress == 12'h305 && dut.m_csrOperation == 2'd1 &&
       dut.m_rd == 5'd0 && !dut.m_load && !dut.m_store && !dut.m_mret &&
       !dut.m_wfi && !dut.m_fenceI &&
       dut.m_nextPc == dut.m_instruction_pc + 32'd4);
// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
// Source closure is joint with the current CSR decode relation C.
  wire core_mtvec_operand_register_R = !dut.mValid ||
      dut.m_instruction_word != 32'h30509073 ||
      dut.m_csrOperand == dut.registers;
// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
// Predicate fragments only; RDmeta is distinct from the debug-break relation.
  wire core_destination_metadata_RDmeta = !dut.mValid ||
      dut.m_rd == dut.m_instruction_word[11:7];
  wire core_noncontrol_nextpc_Nmeta = !dut.mValid ||
      dut.m_instruction_word[6:0] == 7'h63 ||
      dut.m_instruction_word[6:0] == 7'h6f ||
      dut.m_instruction_word[6:0] == 7'h67 ||
      dut.m_nextPc == dut.m_instruction_pc + 32'd4;
  wire core_self_jal_nextpc_Jmeta = !dut.mValid ||
      dut.m_instruction_word != 32'h0000006f || dut.m_trap ||
      dut.m_nextPc == dut.m_instruction_pc;

  always @(posedge clock) begin
    core_native_semantic_metadata: assert(core_sequential_addi_metadata_A && core_mtvec_write_metadata_C && core_mtvec_operand_register_R && core_destination_metadata_RDmeta && core_noncontrol_nextpc_Nmeta && core_self_jal_nextpc_Jmeta);
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  always @(posedge clock) begin
    core_debug_command_register_domain: assert(
        (!dut.dm.busy || dut.dm.commandValid) &&
        (!dut.dm.commandValid || dut.dm.command_register == 16'h07a2 ||
         dut.dm.command_register == 16'h07a1 || dut.dm.command_register == 16'h07a5 ||
         dut.dm.command_register == 16'h0305 || dut.dm.command_register == 16'h07b1 ||
         dut.dm.command_register == 16'h1006));
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
// Predicate fragment only; source closure requires the existing current FX relation.
  wire core_word_load_base_zero_aligned =
      dut.m_instruction_word[6:0] == 7'h03 &&
      dut.m_instruction_word[14:12] == 3'd2 &&
      dut.m_instruction_word[19:15] == 5'd0 &&
      dut.m_instruction_word[21:20] == 2'd0;
  wire core_word_store_base_zero_aligned =
      dut.m_instruction_word[6:0] == 7'h23 &&
      dut.m_instruction_word[14:12] == 3'd2 &&
      dut.m_instruction_word[19:15] == 5'd0 &&
      dut.m_instruction_word[8:7] == 2'd0;
  wire core_memory_trap_metadata_T = !dut.mValid ||
      !(core_word_load_base_zero_aligned || core_word_store_base_zero_aligned) ||
      !dut.m_trap ||
      (dut.m_cause == 32'd3 && dut.m_tval == dut.m_instruction_pc);

  wire core_semantic_fetch_execute_FX = (!dut.fetch.firstValid || !dut.fetch.firstFault) &&
        (!dut.fetch.secondValid || !dut.fetch.secondFault) &&
        (!dut.fetch.buffered || !dut.fetch.packet_fault) &&
        (!dut.xValid || !dut.x_fault);
  always @(posedge clock) begin
    core_native_trap_metadata: assert(core_semantic_fetch_execute_FX && core_memory_trap_metadata_T);
  end

