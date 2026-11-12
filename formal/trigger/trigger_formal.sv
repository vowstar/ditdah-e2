// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module trigger_formal(input clock, input reset);
  reg [11:0] address;
  reg [31:0] operand;
  reg [1:0] operation;
  reg writeRequested, commit, debugAccess;
  reg [31:0] core_pc;
  reg core_valid, core_user, core_debug, core_ready, core_trap, core_mret;
  wire implemented, core_matched, core_debugAction, core_nativeAction;
  wire [31:0] readData, writeMask, writtenData;
  wire observe_selected, observe_mte, observe_mpte;
  wire [1:0] observe_dmode, observe_hit, observe_debugAction, observe_machine, observe_user, observe_execute;
  wire [31:0] observe_address0, observe_address1;
  DitDahE2Trigger dut(.*);

  reg initialized = 0;
  always @($global_clock) begin
    if (!reset) initialized <= 1;
    if (!initialized) initial_common_cold_reset: assume(reset);
    else no_later_cold_reset: assume(!reset);
  end
  reg past_valid = 0, past_reset = 1;
  wire check = past_valid && !reset && !past_reset;
  always @(posedge clock or posedge reset) begin
    if (reset || !initialized) begin
      past_reset <= 1;
      past_valid <= 0;
    end else begin
      past_reset <= reset;
      past_valid <= 1;
    end
  end

  wire selected0 = !observe_selected;
  wire selected1 = observe_selected;
  wire csr_write = commit && writeRequested && implemented;
  wire match0 = core_valid && !core_debug && observe_execute[0] &&
                (core_user ? observe_user[0] : observe_machine[0]) &&
                (core_user || observe_debugAction[0] || observe_mte) && core_pc == observe_address0;
  wire match1 = core_valid && !core_debug && observe_execute[1] &&
                (core_user ? observe_user[1] : observe_machine[1]) &&
                (core_user || observe_debugAction[1] || observe_mte) && core_pc == observe_address1;

  always @(posedge clock) begin
    if (check) begin
      tinfo_version: assert(address != 12'h7a4 || readData == 32'h01000004);
      unsupported_context_zero: assert((address != 12'h7a3 && address != 12'h7a8 && address != 12'h7aa) || readData == 0);
      mcontrol_type: assert(address != 12'h7a1 || readData[31:28] == 2);
      mcontrol_reserved_zero: assert(address != 12'h7a1 ||
        (readData[26:21] == 0 && readData[19:18] == 0 && readData[17:16] == 0 &&
         readData[11] == 0 && readData[10:7] == 0 && readData[5:4] == 0 && readData[1:0] == 0));
      legal_debug_action0: assert(observe_dmode[0] || !observe_debugAction[0]);
      legal_debug_action1: assert(observe_dmode[1] || !observe_debugAction[1]);
      debug_excludes_native: assert(!core_debugAction || !core_nativeAction);
      native_excludes_debug: assert(!core_nativeAction || !core_debugAction);
      debug_mode_quiet: assert(!core_debug || !core_matched);
      native_machine_enable: assert(!core_nativeAction || core_user || observe_mte);
      exact_match0: assert(!match0 || core_matched);
      exact_match1: assert(!match1 || core_matched);
      wrong_address0: assert(core_pc == observe_address0 || !core_valid || core_debug || !observe_execute[0] ||
                             !(core_user ? observe_user[0] : observe_machine[0]) || !core_matched || match1);
      wrong_address1: assert(core_pc == observe_address1 || !core_valid || core_debug || !observe_execute[1] ||
                             !(core_user ? observe_user[1] : observe_machine[1]) || !core_matched || match0);
      if ($past(!reset && core_ready && match0)) hit0_set: assert(observe_hit[0]);
      if ($past(!reset && core_ready && match1)) hit1_set: assert(observe_hit[1]);
      if ($past(!reset && core_ready && match0 && match1)) simultaneous_hits_set: assert(observe_hit == 3);
      if ($past(!reset && core_trap)) trap_saves_mte: assert(!observe_mte && observe_mpte == $past(observe_mte));
      if ($past(!reset && core_mret && !core_trap)) mret_restores_mte: assert(observe_mte == $past(observe_mpte));
      if ($past(!reset && !debugAccess && csr_write && address == 12'h7a1 && selected0))
        dmode0_only_debug: assert(observe_dmode[0] == $past(observe_dmode[0]));
      if ($past(!reset && !debugAccess && csr_write && address == 12'h7a1 && selected1))
        dmode1_only_debug: assert(observe_dmode[1] == $past(observe_dmode[1]));
      if ($past(!reset && observe_dmode[0] && !debugAccess && csr_write && selected0 &&
                (address == 12'h7a1 || address == 12'h7a2))) begin
        locked0_control: assert($stable(observe_debugAction[0]) && $stable(observe_machine[0]) &&
                                $stable(observe_user[0]) && $stable(observe_execute[0]) && $stable(observe_address0));
      end
      if ($past(!reset && observe_dmode[1] && !debugAccess && csr_write && selected1 &&
                (address == 12'h7a1 || address == 12'h7a2))) begin
        locked1_control: assert($stable(observe_debugAction[1]) && $stable(observe_machine[1]) &&
                                $stable(observe_user[1]) && $stable(observe_execute[1]) && $stable(observe_address1));
      end
      cover_simultaneous: cover(core_ready && match0 && match1 && observe_debugAction[0] != observe_debugAction[1]);
      cover_native: cover(core_nativeAction);
      cover_debug: cover(core_debugAction);
      cover_trap_mret: cover($past(!reset && core_trap) && core_mret);
      cover_user: cover(core_user && core_nativeAction);
      cover_debug_mode: cover(core_debug && core_valid);
    end
  end
endmodule
