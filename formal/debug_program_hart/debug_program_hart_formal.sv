// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module debug_program_hart_formal(
  input clock, input reset,
  input debug_request_valid, output debug_request_ready,
  input debug_request_bits_memory, input debug_request_bits_write,
  input [1:0] debug_request_bits_size,
  input [15:0] debug_request_bits_register,
  input [31:0] debug_request_bits_address, input [31:0] debug_request_bits_data,
  input debug_request_bits_transfer, input debug_request_bits_postExec,
  input [31:0] debug_request_bits_program0, input [31:0] debug_request_bits_program1,
  output debug_response_valid, input debug_response_ready,
  output [31:0] debug_response_bits_data,
  output [2:0] debug_response_bits_error,
  output debug_response_bits_dataValid,
  input debug_control_active, input debug_control_halt,
  input debug_control_resume, input debug_control_reset,
  input debug_control_haltOnReset,
  output debug_status_halted, output debug_status_running,
  output debug_status_unavailable, output debug_status_resetEvent,
  output debug_status_resumeAck, output debug_status_resetPending,
  input core_empty, input core_fetchIdle,
  input [31:0] core_architecturalPc,
  input core_userMode, input core_completed, input core_breakpoint,
  input [31:0] core_breakpointPc,
  input core_injectedIdle, input core_injectionDone_valid,
  input [2:0] core_injectionDone_sequence,
  input core_injectionDone_fault, input core_injectionDone_ebreak,
  output core_stop, output core_resume,
  output [31:0] core_resumePc,
  output core_resumeUser, output core_coreReset,
  output core_singleStep, output core_ebreakMachine,
  output core_ebreakUser, output core_freezeCounters,
  output core_entry, output core_injectionActive,
  output core_injection_valid, input core_injection_ready,
  output [31:0] core_injection_bits_word,
  output [2:0] core_injection_bits_length,
  output [2:0] core_injection_bits_sequence,
  output core_injection_bits_truncated,
  input [11:0] core_localCsr_address,
  input [31:0] core_localCsr_operand,
  input [1:0] core_localCsr_operation,
  input core_localCsr_writeRequested, input core_localCsr_commit,
  output [31:0] core_localCsr_readData,
  output [31:0] core_localCsr_writeMask,
  output [31:0] core_localCsr_writtenData,
  output [15:0] backend_register,
  output backend_writeRequested, output backend_writePulse,
  output [31:0] backend_writeData,
  input [31:0] backend_readData, input backend_error,
  output [31:0] protection_address,
  output [1:0] protection_size,
  output protection_write,
  input protection_allowed, input protection_machine,
  output memory_request_valid, input memory_request_ready,
  output [31:0] memory_request_bits_address,
  output memory_request_bits_machine, output memory_request_bits_write,
  output [31:0] memory_request_bits_data,
  output [3:0] memory_request_bits_mask,
  output [1:0] memory_request_bits_size,
  output [3:0] memory_request_bits_operation,
  input memory_response_valid, output memory_response_ready,
  input [31:0] memory_response_bits_data,
  input memory_response_bits_fault
);
  DitDahE2DebugHart dut (.*);

  reg initialized = 0;
  always @($global_clock) begin
    initialized <= 1;
  end

  function automatic [1:0] program_raw(input [2:0] sequence_index,
      input [31:0] program0, input [31:0] program1);
    case (sequence_index)
      0: program_raw = program0[1:0];
      1: program_raw = program0[17:16];
      2: program_raw = program1[1:0];
      3: program_raw = program1[17:16];
      default: program_raw = 0;
    endcase
  endfunction

  function automatic [31:0] program_word(input [2:0] sequence_index,
      input [31:0] program0, input [31:0] program1);
    case (sequence_index)
      0: program_word = program0[1:0] == 3 ? program0 : {16'h0, program0[15:0]};
      1: program_word = program0[17:16] == 3 ?
           {program1[15:0], program0[31:16]} : {16'h0, program0[31:16]};
      2: program_word = program1[1:0] == 3 ? program1 : {16'h0, program1[15:0]};
      3: program_word = {16'h0, program1[31:16]};
      4: program_word = 32'h00100073;
      default: program_word = 32'h0;
    endcase
  endfunction

  function automatic [2:0] program_length(input [2:0] sequence_index,
      input [31:0] program0, input [31:0] program1);
    program_length = sequence_index == 4 || program_raw(sequence_index, program0, program1) == 3 ? 4 : 2;
  endfunction

  reg past_valid = 0;
  reg past_reset = 1;
  reg request_blocked = 0;
  reg [149:0] request_hold;
  reg model_program_active = 0;
  reg model_pending = 0;
  reg model_outstanding = 0;
  reg model_cancelling = 0;
  reg [2:0] model_slot = 0;
  reg [31:0] model_program0 = 0;
  reg [31:0] model_program1 = 0;
  reg [3:0] model_issue_count = 0;
  reg model_single_ebreak = 0;
  reg model_cancel_waited = 0;
  reg model_cancel_reset = 0;
  reg model_memory_debt = 0;
  reg model_memory_deactivated = 0;
  reg model_memory_reset = 0;

  wire request_accept = debug_request_valid && debug_request_ready;
  wire local_register = debug_request_bits_register == 16'h7b0 ||
                        debug_request_bits_register == 16'h7b1;
  wire legal_format = debug_request_bits_memory ?
                      debug_request_bits_size != 3 && !debug_request_bits_postExec :
                      !debug_request_bits_transfer || debug_request_bits_size == 2;
  wire transfer_error = debug_request_bits_transfer && !local_register && backend_error;
  wire program_start = request_accept && debug_status_halted && legal_format &&
                       !debug_request_bits_memory && debug_request_bits_postExec && !transfer_error;
  wire issue_fire = core_injection_valid && core_injection_ready;
  wire cancel_event = model_program_active && !model_cancelling &&
                      (!debug_control_active || debug_status_unavailable);
  wire [31:0] expected_word = program_word(model_slot, model_program0, model_program1);
  wire [2:0] expected_length = program_length(model_slot, model_program0, model_program1);
  wire expected_truncated = model_slot == 3 && model_program1[17:16] == 3;
  wire model_terminate = core_injectionDone_valid && model_outstanding && !model_cancelling &&
                         (core_injectionDone_fault || core_injectionDone_ebreak || model_slot == 4);
  wire cancel_finish = model_cancelling && !model_pending && !model_outstanding && core_injectedIdle;
  wire memory_accept = memory_request_valid && memory_request_ready;
  wire memory_return = memory_response_valid && memory_response_ready;
  wire check = past_valid && !reset && !past_reset;

  always @(posedge clock or posedge reset) begin
    if (reset || !initialized) begin
      past_valid <= 0;
      past_reset <= 1;
      request_blocked <= 0;
      request_hold <= 0;
      model_program_active <= 0;
      model_pending <= 0;
      model_outstanding <= 0;
      model_cancelling <= 0;
      model_slot <= 0;
      model_program0 <= 0;
      model_program1 <= 0;
      model_issue_count <= 0;
      model_single_ebreak <= 0;
      model_cancel_waited <= 0;
      model_cancel_reset <= 0;
      model_memory_debt <= 0;
      model_memory_deactivated <= 0;
      model_memory_reset <= 0;
    end else begin
      past_valid <= 1;
      past_reset <= reset;
      if (request_blocked) begin
        debug_request_valid_stable: assume(debug_request_valid);
        debug_request_payload_stable: assume({debug_request_bits_memory, debug_request_bits_write,
          debug_request_bits_size, debug_request_bits_register, debug_request_bits_address,
          debug_request_bits_data, debug_request_bits_transfer, debug_request_bits_postExec,
          debug_request_bits_program0, debug_request_bits_program1} == request_hold);
      end
      request_blocked <= debug_request_valid && !debug_request_ready;
      if (debug_request_valid && !debug_request_ready)
        request_hold <= {debug_request_bits_memory, debug_request_bits_write,
          debug_request_bits_size, debug_request_bits_register, debug_request_bits_address,
          debug_request_bits_data, debug_request_bits_transfer, debug_request_bits_postExec,
          debug_request_bits_program0, debug_request_bits_program1};
      injection_done_has_accepted_issue: assume(!core_injectionDone_valid || model_outstanding);
      injection_done_sequence_matches: assume(!core_injectionDone_valid ||
                                              core_injectionDone_sequence == model_slot);
      injection_done_ebreak_decoded: assume(!core_injectionDone_valid ||
        expected_word != 32'h00100073 || core_injectionDone_ebreak);
      injected_idle_has_no_accepted_issue: assume(!core_injectedIdle || !model_outstanding);
      memory_response_has_accepted_request: assume(!memory_response_valid || model_memory_debt);

      if (check) begin
        transfer_zero_no_backend_write: assert(!backend_writePulse || debug_request_bits_transfer);
        postexec_only_no_backend_write: assert(!(program_start && !debug_request_bits_transfer &&
                                                 backend_writePulse));
        program_blocks_backend_write: assert(!(core_injectionActive && backend_writePulse));
        program_blocks_new_command: assert(!(core_injectionActive && request_accept));
        injection_valid_matches_model: assert(core_injection_valid ==
          (model_program_active && model_pending && !model_cancelling));
        injection_sequence_matches_model: assert(!core_injection_valid ||
                                                 core_injection_bits_sequence == model_slot);
        program0_fresh_operands: assert(!(core_injection_valid && (model_slot == 0 || model_slot == 1)) ||
                                        core_injection_bits_word == expected_word);
        program1_fresh_operands: assert(!(core_injection_valid && (model_slot == 1 || model_slot == 2 ||
                                        model_slot == 3)) || core_injection_bits_word == expected_word);
        injection_word_matches_program: assert(!core_injection_valid ||
                                               core_injection_bits_word == expected_word);
        injection_length_matches_program: assert(!core_injection_valid ||
                                                 core_injection_bits_length == expected_length);
        cross_word_32bit: assert(!(core_injection_valid && model_slot == 1 &&
          model_program0[17:16] == 3) || (core_injection_bits_word ==
          {model_program1[15:0], model_program0[31:16]} && core_injection_bits_length == 4 &&
          !core_injection_bits_truncated));
        truncated_halfword: assert(!(core_injection_valid && model_slot == 3 &&
          model_program1[17:16] == 3) || (core_injection_bits_truncated &&
          core_injection_bits_word == {16'h0, model_program1[31:16]} &&
          core_injection_bits_length == 4));
        implicit_ebreak: assert(!(core_injection_valid && model_slot == 4) ||
          (core_injection_bits_word == 32'h00100073 && core_injection_bits_length == 4 &&
           core_injection_bits_sequence == 4 && !core_injection_bits_truncated));
        if ($past(core_injection_valid && !core_injection_ready && debug_control_active &&
                  !debug_status_unavailable) && debug_control_active && !debug_status_unavailable) begin
          injection_valid_stable: assert(core_injection_valid);
          injection_payload_stable: assert({core_injection_bits_word, core_injection_bits_length,
            core_injection_bits_sequence, core_injection_bits_truncated} ==
            {$past(core_injection_bits_word), $past(core_injection_bits_length),
             $past(core_injection_bits_sequence), $past(core_injection_bits_truncated)});
        end
        if ($past(model_terminate))
          terminate_ends_injection: assert(!core_injection_valid && !core_injectionActive);
        if ($past(!debug_control_active))
          deactivate_cancels_issue: assert(!core_injection_valid);
        if ($past(debug_status_unavailable))
          reset_cancels_issue: assert(!core_injection_valid);
        cancel_state_has_injection: assert(!dut.cancelInjection || dut.injecting);
        cancel_blocks_response_until_idle: assert(!(model_cancelling && !core_injectedIdle &&
                                                    debug_response_valid));
        program_execution_blocks_response: assert(!(model_program_active && !model_cancelling &&
                                                    debug_response_valid));
        single_postexec_at_most_one_issue: assert(!(model_single_ebreak && model_issue_count > 1));
        memory_response_ready_with_debt: assert(memory_response_ready == model_memory_debt);
        accepted_memory_not_reissued: assert(!(model_memory_debt && memory_request_valid));
        if ($past(model_memory_debt && !debug_control_active) && model_memory_debt)
          deactivate_drains_accepted_memory: assert(memory_response_ready);
        if ($past(model_memory_debt && debug_status_unavailable) && model_memory_debt)
          reset_drains_accepted_memory: assert(memory_response_ready);
      end

      if (request_accept) begin
        model_single_ebreak <= 0;
        model_issue_count <= 0;
        model_cancel_waited <= 0;
        model_cancel_reset <= 0;
      end
      if (program_start) begin
        model_program_active <= 1;
        model_pending <= 1;
        model_outstanding <= 0;
        model_cancelling <= 0;
        model_slot <= 0;
        model_program0 <= debug_request_bits_program0;
        model_program1 <= debug_request_bits_program1;
        model_issue_count <= 0;
        model_single_ebreak <= !debug_request_bits_transfer &&
                               debug_request_bits_program0 == 32'h00100073;
      end else if (model_program_active) begin
        if (issue_fire) begin
          model_pending <= 0;
          model_outstanding <= 1;
          model_issue_count <= model_issue_count + 1;
        end
        if (core_injectionDone_valid) begin
          model_outstanding <= 0;
          if (model_terminate) begin
            model_program_active <= 0;
            model_pending <= 0;
          end else if (!model_cancelling) begin
            model_pending <= 1;
            model_slot <= model_slot + (expected_length == 2 ? 1 : 2);
          end
        end
        if (cancel_event && !model_terminate) begin
          model_cancelling <= 1;
          model_pending <= 0;
          model_cancel_reset <= debug_status_unavailable;
        end
        if (model_cancelling && !core_injectedIdle)
          model_cancel_waited <= 1;
        if (cancel_finish) begin
          model_program_active <= 0;
          model_pending <= 0;
          model_outstanding <= 0;
          model_cancelling <= 0;
        end
      end

      if (memory_accept) begin
        model_memory_debt <= 1;
        model_memory_deactivated <= 0;
        model_memory_reset <= 0;
      end
      if (model_memory_debt && !debug_control_active)
        model_memory_deactivated <= 1;
      if (model_memory_debt && debug_status_unavailable)
        model_memory_reset <= 1;
      if (memory_return) begin
        model_memory_debt <= 0;
        model_memory_deactivated <= 0;
        model_memory_reset <= 0;
      end

      if (check) begin
        cover_postexec_only_start: cover(program_start && !debug_request_bits_transfer);
        cover_postexec_only_single: cover(model_single_ebreak && model_issue_count == 1 &&
          debug_response_valid && debug_response_bits_error == 0 && !backend_writePulse);
        cover_program0_compressed: cover(issue_fire && model_slot == 0 && expected_length == 2);
        cover_program0_32bit: cover(issue_fire && model_slot == 0 && expected_length == 4 &&
                                    core_injection_bits_word == model_program0);
        cover_program1_32bit: cover(issue_fire && model_slot == 2 && expected_length == 4 &&
                                    core_injection_bits_word == model_program1);
        cover_cross_word_32bit: cover(issue_fire && model_slot == 1 && model_program0[17:16] == 3 &&
          core_injection_bits_word == {model_program1[15:0], model_program0[31:16]} &&
          core_injection_bits_length == 4);
        cover_truncated_halfword: cover(issue_fire && model_slot == 3 && model_program1[17:16] == 3 &&
                                        core_injection_bits_truncated);
        cover_implicit_ebreak: cover(issue_fire && model_slot == 4 &&
          core_injection_bits_word == 32'h00100073 && core_injection_bits_length == 4);
        cover_injection_backpressure: cover(core_injection_valid && !core_injection_ready);
        cover_deactivate_cancel_wait: cover(model_cancelling && !debug_control_active &&
          !core_injectedIdle && !debug_response_valid);
        cover_reset_cancel_response: cover(model_cancel_waited && model_cancel_reset &&
          debug_control_active && debug_response_valid && debug_response_bits_error == 4);
        cover_deactivate_memory_drain: cover(memory_return && model_memory_deactivated);
        cover_reset_memory_drain: cover(memory_return && model_memory_reset);
      end
    end
  end
endmodule
