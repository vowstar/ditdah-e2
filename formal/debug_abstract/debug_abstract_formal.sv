// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module debug_abstract_formal(
  input clock, input reset,
  input dmi_request_valid, output dmi_request_ready,
  input [6:0] dmi_request_bits_address,
  input [31:0] dmi_request_bits_data,
  input [1:0] dmi_request_bits_op,
  output dmi_response_valid, input dmi_response_ready,
  output [31:0] dmi_response_bits_data,
  output [1:0] dmi_response_bits_status,
  output hart_request_valid, input hart_request_ready,
  output hart_request_bits_memory, output hart_request_bits_write,
  output [1:0] hart_request_bits_size,
  output [15:0] hart_request_bits_register,
  output [31:0] hart_request_bits_address,
  output [31:0] hart_request_bits_data,
  output hart_request_bits_transfer, output hart_request_bits_postExec,
  output [31:0] hart_request_bits_program0,
  output [31:0] hart_request_bits_program1,
  input hart_response_valid, output hart_response_ready,
  input [31:0] hart_response_bits_data,
  input [2:0] hart_response_bits_error,
  input hart_response_bits_dataValid,
  output hart_control_active, output hart_control_halt,
  output hart_control_resume, output hart_control_reset,
  output hart_control_haltOnReset
);
  wire hart_status_halted = 1'b1;
  wire hart_status_running = 1'b0;
  wire hart_status_unavailable = 1'b0;
  wire hart_status_resetEvent = 1'b0;
  wire hart_status_resumeAck = 1'b0;
  wire hart_status_resetPending = 1'b0;
  DitDahE2DebugModule dut (.*);

  reg initialized = 0;
  always @($global_clock) begin
    if (!reset) initialized <= 1;
    if (!initialized) initial_common_cold_reset: assume(reset);
    else no_later_cold_reset: assume(!reset);
  end

  reg past_valid = 0;
  reg past_reset = 1;
  reg request_blocked = 0;
  reg [40:0] request_hold;
  reg response_owned = 0;
  reg hart_debt = 0;
  reg execution_pending = 0;
  reg [31:0] expected_address, expected_data;
  reg expected_memory, expected_write;
  reg [1:0] expected_size;
  reg [15:0] expected_register;
  reg [31:0] expected_program0, expected_program1;
  wire dmi_accept = dmi_request_valid && dmi_request_ready;
  wire dmi_read = dmi_accept && dmi_request_bits_op == 1;
  wire dmi_write = dmi_accept && dmi_request_bits_op == 2;
  wire dmi_data_access = dmi_request_bits_address == 4 || dmi_request_bits_address == 5;
  wire dmi_auto_access = dmi_data_access || dmi_request_bits_address == 7'h20 ||
                         dmi_request_bits_address == 7'h21;
  wire dmi_deactivate = dmi_write && dmi_request_bits_address == 7'h10 && !dmi_request_bits_data[0];
  wire dmi_return = dmi_response_valid && dmi_response_ready;
  wire hart_accept = hart_request_valid && hart_request_ready;
  wire auto_start = dut.autoStart_1;
  wire manual_start = dut.manualStart;
  wire start = auto_start || manual_start;
  wire start_memory = auto_start ? dut.command_memory : dmi_request_bits_data[31:24] == 2;
  wire start_transfer = auto_start ? dut.command_transfer : dmi_request_bits_data[17];
  wire start_postexec = auto_start ? dut.command_postExec : dmi_request_bits_data[18];
  wire start_needs_hart = start_memory || start_transfer || start_postexec;
  wire [31:0] start_address = auto_start && dmi_write && dmi_request_bits_address == 5 ?
                              dmi_request_bits_data : dut.data1;
  wire [31:0] start_data = auto_start && dmi_write && dmi_request_bits_address == 4 ?
                           dmi_request_bits_data : dut.data0;
  wire [31:0] start_program0 = auto_start && dmi_write && dmi_request_bits_address == 7'h20 ?
                               dmi_request_bits_data : dut.program0;
  wire [31:0] start_program1 = auto_start && dmi_write && dmi_request_bits_address == 7'h21 ?
                               dmi_request_bits_data : dut.program1;
  wire conflict = dut.active && dut.busy &&
                  ((dmi_read || dmi_write) && dmi_auto_access ||
                   dmi_write && (dmi_request_bits_address == 7'h16 ||
                                 dmi_request_bits_address == 7'h17 ||
                                 dmi_request_bits_address == 7'h18));
  wire register_supported = dmi_request_bits_data[31:24] == 0 &&
                            !dmi_request_bits_data[23] && !dmi_request_bits_data[19] &&
                            (!dmi_request_bits_data[17] || dmi_request_bits_data[22:20] == 2);
  wire memory_supported = dmi_request_bits_data[31:24] == 2 &&
                          !dmi_request_bits_data[23] && dmi_request_bits_data[22:20] <= 2 &&
                          dmi_request_bits_data[18:17] == 0 && dmi_request_bits_data[15:0] == 0;
  wire command_attempt = dmi_write && dmi_request_bits_address == 7'h17 &&
                         dut.active && !dut.busy && dut.error == 0;
  wire successful_post = dut.commandComplete && dut.command_memory &&
                         dut.command_postIncrement && hart_response_bits_error == 0;
  wire check = past_valid && !reset && !past_reset;

  always @(posedge clock or posedge reset) begin
    if (reset || !initialized) begin
      past_reset <= 1;
      past_valid <= 0;
      request_blocked <= 0;
      request_hold <= 0;
      response_owned <= 0;
      hart_debt <= 0;
      execution_pending <= 0;
      expected_address <= 0;
      expected_data <= 0;
      expected_memory <= 0;
      expected_write <= 0;
      expected_size <= 0;
      expected_register <= 0;
      expected_program0 <= 0;
      expected_program1 <= 0;
    end else begin
      past_reset <= reset;
      past_valid <= 1;
      if (request_blocked) begin
        dmi_request_valid_stable: assume(dmi_request_valid);
        dmi_request_payload_stable: assume({dmi_request_bits_address, dmi_request_bits_data,
                                            dmi_request_bits_op} == request_hold);
      end
      request_blocked <= dmi_request_valid && !dmi_request_ready;
      if (dmi_request_valid && !dmi_request_ready)
        request_hold <= {dmi_request_bits_address, dmi_request_bits_data, dmi_request_bits_op};
      hart_response_has_request: assume(!hart_response_valid || hart_debt);
      hart_response_error_supported: assume(hart_response_bits_error <= 5);
      if (hart_accept) hart_debt <= 1;
      if (hart_response_valid) hart_debt <= 0;
      if (dmi_accept) response_owned <= 1;
      if (dmi_return) response_owned <= 0;
      if (!past_valid && dmi_response_valid && !dmi_return) response_owned <= 1;
      if ((!dut.active || dmi_deactivate)) execution_pending <= 0;
      else begin
        if (start && start_needs_hart) begin
          if (check) start_without_pending_request: assert(!execution_pending);
          execution_pending <= 1;
        end
        if (hart_accept) begin
          if (check) hart_request_accepted_once: assert(execution_pending);
          execution_pending <= 0;
        end
      end
      if (start && start_needs_hart) begin
        expected_address <= start_address;
        expected_data <= start_data;
        expected_memory <= start_memory;
        expected_write <= auto_start ? dut.command_write : dmi_request_bits_data[16];
        expected_size <= auto_start ? dut.command_size : dmi_request_bits_data[21:20];
        expected_register <= auto_start ? dut.command_register : dmi_request_bits_data[15:0];
        expected_program0 <= start_program0;
        expected_program1 <= start_program1;
      end
      if (!past_valid && hart_request_valid && !start && !hart_accept) begin
        execution_pending <= 1;
        expected_address <= hart_request_bits_address;
        expected_data <= hart_request_bits_data;
        expected_memory <= hart_request_bits_memory;
        expected_write <= hart_request_bits_write;
        expected_size <= hart_request_bits_size;
        expected_register <= hart_request_bits_register;
        expected_program0 <= hart_request_bits_program0;
        expected_program1 <= hart_request_bits_program1;
      end

      if (check) begin
        if (dmi_response_valid) dmi_response_has_owner: assert(response_owned);
        if (response_owned) dmi_request_blocked_with_response: assert(!dmi_request_ready);
        if (hart_request_valid) hart_request_has_start: assert(execution_pending);
        if (execution_pending && hart_request_valid) begin
          fresh_operands: assert({hart_request_bits_address, hart_request_bits_data} ==
                                 {expected_address, expected_data});
          fresh_program_operands: assert({hart_request_bits_program0, hart_request_bits_program1} ==
                                         {expected_program0, expected_program1});
          stable_command_description: assert({hart_request_bits_memory, hart_request_bits_write,
                                              hart_request_bits_size, hart_request_bits_register} ==
                                             {expected_memory, expected_write, expected_size, expected_register});
        end
        auto_requires_accepted_dmi: assert(!auto_start ||
                                           (dmi_accept && (dmi_read || dmi_write) && dmi_auto_access));
        auto_requires_enabled_access: assert(!auto_start ||
                                             (dmi_request_bits_address == 4 && dut.auto[0] ||
                                              dmi_request_bits_address == 5 && dut.auto[1] ||
                                              dmi_request_bits_address == 7'h20 && dut.auto[16] ||
                                              dmi_request_bits_address == 7'h21 && dut.auto[17]));
        if ($past(manual_start && dmi_request_bits_data[18] && !(!dut.active || dmi_deactivate)))
          postexec_start_has_request: assert(execution_pending && dut.needsHart);
        if ($past(manual_start && dmi_request_bits_data[18] && !dmi_request_bits_data[17] &&
                  !(!dut.active || dmi_deactivate)) && !(dmi_write && dmi_request_bits_address == 4))
          postexec_only_preserves_data: assert(dut.data0 == $past(dut.data0));
        if ($past(dut.commandComplete && hart_response_bits_dataValid && !(!dut.active || dmi_deactivate)))
          data_valid_updates_data0: assert(dut.data0 == $past(hart_response_bits_data));
        if (dut.error != 0) error_blocks_new_command: assert(!manual_start && !auto_start);
      end

      if (check) begin
        if ($past(dmi_response_valid && !dmi_response_ready)) begin
          dmi_response_valid_stable: assert(dmi_response_valid);
          dmi_response_payload_stable: assert({dmi_response_bits_data, dmi_response_bits_status} ==
                                               {$past(dmi_response_bits_data), $past(dmi_response_bits_status)});
        end
        if ($past(hart_request_valid && !hart_request_ready && !dmi_deactivate)) begin
          hart_request_valid_stable: assert(hart_request_valid);
          hart_request_payload_stable: assert({hart_request_bits_memory, hart_request_bits_write,
                                                hart_request_bits_size, hart_request_bits_register,
                                                hart_request_bits_address, hart_request_bits_data,
                                                hart_request_bits_transfer, hart_request_bits_postExec,
                                                hart_request_bits_program0, hart_request_bits_program1} ==
                                               {$past(hart_request_bits_memory), $past(hart_request_bits_write),
                                                $past(hart_request_bits_size), $past(hart_request_bits_register),
                                                $past(hart_request_bits_address), $past(hart_request_bits_data),
                                                $past(hart_request_bits_transfer), $past(hart_request_bits_postExec),
                                                $past(hart_request_bits_program0), $past(hart_request_bits_program1)});
        end
        if ($past(dmi_read && dmi_request_bits_address == 4 && dut.active && !dut.busy))
          data0_read_returns_previous: assert(dmi_response_valid &&
                                              dmi_response_bits_data == $past(dut.data0));
        if ($past(dmi_read && dmi_request_bits_address == 7'h18 && dut.active))
          abstractauto_reserved_bits_zero: assert(dmi_response_valid &&
                                                  dmi_response_bits_data == {14'b0, $past(dut.auto)});
        if ($past(dmi_read && dmi_request_bits_address == 7'h16 && dut.active))
          program_buffer_size_is_two: assert(dmi_response_valid && dmi_response_bits_data[28:24] == 2);
        if ($past(dmi_read && dmi_request_bits_address == 7'h11 && dut.active))
          implicit_ebreak_is_advertised: assert(dmi_response_valid && dmi_response_bits_data[22]);
        data1_update_exactly_once: assert(
          $past((!dut.active || dmi_deactivate)) ? dut.data1 == 0 :
          $past(successful_post) ?
            dut.data1 == $past(dut.operands_address) +
              ($past(dut.command_size) == 0 ? 1 : $past(dut.command_size) == 1 ? 2 : 4) :
          $past(dmi_write && dmi_request_bits_address == 5 && dut.active && !dut.busy) ?
            dut.data1 == $past(dmi_request_bits_data) : dut.data1 == $past(dut.data1));
        if ($past(conflict && dut.error == 0 && !(!dut.active || dmi_deactivate)))
          busy_conflict_priority: assert(dut.error == 1);
        if ($past(conflict && dut.error != 0 && !(!dut.active || dmi_deactivate)))
          busy_conflict_preserves_error: assert(dut.error == $past(dut.error));
        if ($past(dut.commandComplete && dut.command_memory && dut.error == 0 &&
                  !conflict && hart_response_bits_error == 5 && !(!dut.active || dmi_deactivate)))
          memory_bus_error_is_five: assert(dut.error == 5);
        if ($past(dut.commandComplete && !dut.command_memory && dut.command_postExec && dut.error == 0 &&
                  !conflict && hart_response_bits_error == 3 && !(!dut.active || dmi_deactivate)))
          postexec_error_is_three: assert(dut.error == 3);
        if ($past(command_attempt && !(register_supported || memory_supported)))
          unsupported_command_error: assert(dut.error == 2);
        if ($past(dmi_deactivate))
          deactivate_clears_command_state: assert(!dut.busy && !dut.commandValid && dut.auto == 0 &&
                                                  dut.data0 == 0 && dut.data1 == 0 && dut.error == 0 &&
                                                  dut.program0 == 0 && dut.program1 == 0);
      end

      if (check) begin
        cover_auto_write_data: cover(auto_start && dmi_write && dmi_request_bits_address == 4 &&
                                     dut.command_memory && dut.command_write && dut.command_postIncrement);
        cover_auto_write_address: cover(auto_start && dmi_write && dmi_request_bits_address == 5 &&
                                        dut.command_memory && dut.command_write && dut.command_postIncrement);
        cover_auto_read_data: cover(auto_start && dmi_read && dmi_request_bits_address == 4 &&
                                    dut.command_memory && !dut.command_write && dut.command_postIncrement);
        cover_auto_response_backpressure: cover($past(auto_start) && dmi_response_valid && !dmi_response_ready);
        cover_successful_postincrement: cover(successful_post);
        cover_fault_without_postincrement: cover(dut.commandComplete && dut.command_memory &&
                                                 dut.command_postIncrement && hart_response_bits_error != 0);
        cover_busy_conflict_with_fault: cover(conflict && dut.commandComplete && dut.error == 0 &&
                                              hart_response_bits_error == 5);
        cover_deactivate_with_completion: cover(dmi_deactivate && dut.commandComplete);
        cover_postexec_only: cover(start && !start_memory && !start_transfer && start_postexec);
        cover_postexec_with_transfer: cover(manual_start && dmi_request_bits_data[18] && dmi_request_bits_data[17]);
        cover_program_auto_high: cover(auto_start && dmi_write && dmi_data_access == 0 &&
                                       (dmi_request_bits_address == 7'h20 || dmi_request_bits_address == 7'h21) &&
                                       dut.command_postExec);
        cover_read_then_fault_preserves_data: cover(dut.commandComplete && dut.command_postExec &&
                                                    hart_response_bits_dataValid && hart_response_bits_error == 3);
      end
    end
  end
endmodule
