// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire core_program_no_injection_I = (!dut.dm.busy || dut.dm.commandValid) &&
      (!dut.dm.commandValid || !dut.dm.command_postExec) && !dut.debug.injecting &&
      !dut.debug.pendingIssue && !dut.xInjected && (!dut.mValid || !dut.m_injected);
// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire rom_local_response_safe = instruction_response_bits_data != 32'h10500073 &&
      instruction_response_bits_data != 32'h00100073 &&
      !(instruction_response_bits_data[6:0] == 7'h0f && instruction_response_bits_data[14:12] == 3'b001);
  always @($global_clock) begin
    rom_local_response_class: assert(rom_local_response_safe);
  end
// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire rom_local_first_safe = dut.fetch.firstWord != 32'h10500073 &&
      dut.fetch.firstWord != 32'h00100073 &&
      !(dut.fetch.firstWord[6:0] == 7'h0f && dut.fetch.firstWord[14:12] == 3'b001);
  wire rom_local_second_safe = dut.fetch.secondWord != 32'h10500073 &&
      dut.fetch.secondWord != 32'h00100073 &&
      !(dut.fetch.secondWord[6:0] == 7'h0f && dut.fetch.secondWord[14:12] == 3'b001);
  wire rom_local_packet_safe = dut.fetch.packet_word != 32'h10500073 &&
      dut.fetch.packet_word != 32'h00100073 &&
      !(dut.fetch.packet_word[6:0] == 7'h0f && dut.fetch.packet_word[14:12] == 3'b001);
  always @(posedge clock) begin
    rom_local_valid_word_class: assert((!dut.fetch.firstValid || rom_local_first_safe) &&
          (!dut.fetch.secondValid || rom_local_second_safe) &&
          (!dut.fetch.buffered || rom_local_packet_safe));
  end
// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  always @(posedge clock) begin
    rom_local_fetch_rom_consistent: assert((!dut.fetch.outstanding ||
        (instruction_busy && instruction_address == dut.fetch.address)) &&
        (!dut.fetch.firstValid || dut.fetch.firstWord == rom(dut.fetch.firstAddress)) &&
        (!dut.fetch.secondValid || dut.fetch.secondWord == rom(dut.fetch.secondAddress)));
  end
// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  // Pause discards a stream without rewinding its request cursor.
  reg core_geom_sync_epoch = 0;
  always @(posedge clock) begin
    if (dut.fetch.reset || dut.fetch.redirect) core_geom_sync_epoch <= 1;
    else if (dut.fetch.pause) core_geom_sync_epoch <= 0;
  end
  wire core_geom_live_outstanding = dut.fetch.outstanding && !dut.fetch.discarded;
  wire core_geom_live_held = dut.fetch.held && !dut.fetch.heldDiscarded;
  wire [2:0] core_geom_occupancy = {2'b00, dut.fetch.firstValid} + {2'b00, dut.fetch.secondValid} +
      {2'b00, core_geom_live_outstanding} + {2'b00, core_geom_live_held};
  wire [31:0] core_geom_aligned_pc = {dut.fetch.assemblyPc[31:2], 2'b00};
  wire [31:0] core_geom_queue_bytes = (dut.fetch.firstValid ? 32'd4 : 0) + (dut.fetch.secondValid ? 32'd4 : 0);
  wire [31:0] core_geom_outstanding_bytes = core_geom_live_outstanding ? 32'd4 : 0;
  wire [31:0] core_geom_held_bytes = core_geom_live_held ? 32'd4 : 0;
  wire core_geom_shape = (!dut.fetch.secondValid || dut.fetch.firstValid) &&
      !(dut.fetch.held && dut.fetch.outstanding) && core_geom_occupancy <= 2;
  wire core_geom_geometry = (!dut.fetch.firstValid || dut.fetch.firstAddress == core_geom_aligned_pc) &&
      (!dut.fetch.secondValid || dut.fetch.secondAddress == core_geom_aligned_pc + 4) &&
      (!core_geom_live_outstanding || dut.fetch.address == core_geom_aligned_pc + core_geom_queue_bytes) &&
      (!core_geom_live_held || dut.fetch.heldAddress == core_geom_aligned_pc + core_geom_queue_bytes + core_geom_outstanding_bytes) &&
      dut.fetch.nextWord == core_geom_aligned_pc + core_geom_queue_bytes + core_geom_outstanding_bytes + core_geom_held_bytes;
  wire core_geom_packet_rom = !core_geom_sync_epoch || !dut.fetch.buffered ||
      dut.fetch.packet_word == rom({dut.fetch.packet_pc[31:2], 2'b00});
  always @(posedge clock) begin
    core_geom_rom_packet_consistent: assert(((!dut.fetch.outstanding ||
        (instruction_busy && instruction_address == dut.fetch.address)) &&
        (!dut.fetch.firstValid || dut.fetch.firstWord == rom(dut.fetch.firstAddress)) &&
        (!dut.fetch.secondValid || dut.fetch.secondWord == rom(dut.fetch.secondAddress))) && core_geom_shape && (!core_geom_sync_epoch || core_geom_geometry) && core_geom_packet_rom);
  end
// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  always @(posedge clock) begin
    rom_local_fetch_fault_free: assert((!dut.fetch.firstValid || !dut.fetch.firstFault) &&
        (!dut.fetch.secondValid || !dut.fetch.secondFault) &&
        (!dut.fetch.buffered || !dut.fetch.packet_fault));
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire core_stage_admission_joint = core_geom_sync_epoch || dut._debug_core_stop || dut.sleeping_0 || (dut.mValid && dut.m_fenceI && !dut.m_trap);
  wire core_stage_rom_identity = (!dut.xValid || dut.x_word == rom({dut.x_pc[31:2], 2'b00})) && (!dut.mValid || dut.m_instruction_word == rom({dut.m_instruction_pc[31:2], 2'b00}));
  wire core_stage_consume = dut._fetch_output_valid && dut.fetch_output_ready;
  wire core_stage_admission_safe = dut.driveTrap || !core_stage_consume || core_geom_sync_epoch;
  always @(posedge clock) begin
    core_frontend_stage_rom_consistent: assert((((!dut.fetch.outstanding ||
        (instruction_busy && instruction_address == dut.fetch.address)) &&
        (!dut.fetch.firstValid || dut.fetch.firstWord == rom(dut.fetch.firstAddress)) &&
        (!dut.fetch.secondValid || dut.fetch.secondWord == rom(dut.fetch.secondAddress))) && core_geom_shape && (!core_geom_sync_epoch || core_geom_geometry) && core_geom_packet_rom) &&
        (core_geom_sync_epoch || dut._debug_core_stop || dut.sleeping_0 || (dut.mValid && dut.m_fenceI && !dut.m_trap)) &&
        ((!dut.xValid || dut.x_word == rom({dut.x_pc[31:2], 2'b00})) && (!dut.mValid || dut.m_instruction_word == rom({dut.m_instruction_pc[31:2], 2'b00}))));
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire core_decode_lw_zero = dut.m_instruction_word[6:0] == 7'h03 &&
      dut.m_instruction_word[14:12] == 3'b010 && dut.m_instruction_word[19:15] == 5'd0;
  wire core_decode_sw_zero = dut.m_instruction_word[6:0] == 7'h23 &&
      dut.m_instruction_word[14:12] == 3'b010 && dut.m_instruction_word[19:15] == 5'd0;
  wire [31:0] core_decode_i_immediate = {{20{dut.m_instruction_word[31]}}, dut.m_instruction_word[31:20]};
  wire [31:0] core_decode_s_immediate = {{20{dut.m_instruction_word[31]}}, dut.m_instruction_word[31:25], dut.m_instruction_word[11:7]};
  always @(posedge clock) begin
    core_base_zero_memory_decode: assert(!dut.mValid ||
        ((!core_decode_lw_zero || (dut.m_load && !dut.m_store && dut.m_size == 2 &&
            dut.m_address == core_decode_i_immediate && !dut.m_unsignedLoad)) &&
         (!core_decode_sw_zero || (dut.m_store && !dut.m_load && dut.m_size == 2 &&
            dut.m_address == core_decode_s_immediate))));
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire core_data_owner_active = data_busy && dut.sent && dut.mValid && (dut.m_load || dut.m_store);
  wire core_data_owner_C = !core_data_owner_active ||
      (data_address == dut.m_address && data_write == dut.m_store);
  wire core_data_halt_P = !dut.debug.halted || !dut.mValid || dut.m_trap;
  wire core_data_memory_A = !(dut.debug.sending || dut.debug.waiting) || dut.debug.halted;
  wire core_data_reset_R = !dut.debug.resetting || !(dut.debug.sending || dut.debug.waiting);
  always @(posedge clock) begin
    core_data_owner_control_consistent: assert(core_program_no_injection_I && core_data_owner_C && core_data_halt_P && core_data_memory_A && core_data_reset_R);
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  always @(posedge clock) begin
    core_fetch_execute_fault_free: assert((!dut.fetch.firstValid || !dut.fetch.firstFault) &&
        (!dut.fetch.secondValid || !dut.fetch.secondFault) &&
        (!dut.fetch.buffered || !dut.fetch.packet_fault) &&
        (!dut.xValid || !dut.x_fault));
  end

  always @(posedge clock) begin
    core_program_no_injection: assert(core_program_no_injection_I);
  end

// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
  wire [6:0] core_reverse_opcode = dut.m_instruction_word[6:0];
  wire [2:0] core_reverse_function = dut.m_instruction_word[14:12];
  always @(posedge clock) begin
    core_reverse_memory_system_decode: assert(!dut.mValid ||
        ((!dut.m_load || (core_reverse_opcode == 7'h03 &&
            (core_reverse_function < 3 || core_reverse_function == 4 || core_reverse_function == 5))) &&
         (!dut.m_store || (core_reverse_opcode == 7'h23 && core_reverse_function < 3)) &&
         (!dut.m_csr || (core_reverse_opcode == 7'h73 && dut.m_instruction_word[13:12] != 0)) &&
         (!dut.m_mret || dut.m_instruction_word == 32'h30200073) &&
         (!dut.m_wfi || dut.m_instruction_word == 32'h10500073) &&
         (!dut.m_fenceI || (core_reverse_opcode == 7'h0f && core_reverse_function == 1))));
  end
