// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module atomic_memory_formal(input clock);
  localparam [31:0] BASE = @BASE@;
  localparam integer WORDS = @WORDS@;
  reg reset = 1;
  always @(posedge clock) reset <= 0;
`ifdef OWNERSHIP_COVER
  reg [2:0] scenario = 0;
  reg sent = 0;
  reg [3:0] issued = 0;
  wire [1:0] scenario_port = scenario == 3 ? 2 : scenario == 5 ? 3 : 1;
  wire [3:0] scenario_operation = scenario == 0 || scenario == 2 || scenario == 4 ? 1 : scenario == 1 ? 2 : 0;
  wire scenario_write = scenario_operation != 1;
  wire [3:0] source_valid = scenario == 7 ? ~issued : scenario == 6 || sent ? 4'b0 : (4'b1 << scenario_port);
  wire [3:0] source_ready = scenario == 7 ? 4'b0 : 4'hf;
  wire source_clear = scenario == 6;
  wire [3:0] source_write = {4{scenario != 7 && scenario_write}};
  wire [15:0] source_operation = {4{scenario == 7 ? 4'b0 : scenario_operation}};
`else
  (* anyseq *) reg [3:0] source_valid, source_ready;
  (* anyseq *) reg source_clear;
`ifdef REACHABILITY
  (* anyseq *) reg [3:0] source_write;
  (* anyseq *) reg [15:0] source_operation;
`endif
`endif
`ifdef REACHABILITY
  wire [303:0] source_payload;
  generate for (genvar stimulus_port = 0; stimulus_port < 4; stimulus_port = stimulus_port + 1) begin
    assign source_payload[stimulus_port*76 +: 76] = {BASE, 1'b1, source_write[stimulus_port], 32'h80000001,
      source_write[stimulus_port] ? 4'hf : 4'b0, 2'd2, source_operation[stimulus_port*4 +: 4]};
  end endgenerate
`else
  (* anyseq *) reg [303:0] source_payload;
`endif
  reg initialized = 0, init_waiting = 0;
  reg [@INDEX_HIGH@:0] init_word = 0;
  wire [31:0] init_address = BASE + init_word * 4;
  wire [31:0] init_data = 32'h10203040 ^ (init_word * 32'h01020408);
  wire [75:0] init_payload = {init_address, 1'b1, 1'b1, init_data, 4'hf, 2'd2, 4'd0};
  wire [3:0] request_valid = reset ? 0 : initialized ? source_valid : {1'b0, !init_waiting, 2'b0};
  wire [303:0] payload = initialized ? source_payload : {76'b0, init_payload, 152'b0};
  wire [3:0] response_ready = initialized ? source_ready : 4'hf;
  wire clearReservation = initialized && source_clear;
  wire [3:0] request_ready, response_valid, response_fault;
  wire [127:0] response_data;
  wire formalRead;
  wire [@INDEX_HIGH@:0] formalAddress;
  wire [3:0] formalMask;
  wire [31:0] formalWriteData, formalReadData;
  wire [WORDS*32-1:0] formalMemory;
  @INSTANCE@

  wire [3:0] accepted = request_valid & request_ready;
  wire [3:0] returned = response_valid & response_ready;
`ifdef OWNERSHIP_COVER
  always @(posedge clock) begin
    if (reset || !initialized) begin
      scenario <= 0;
      sent <= 0;
      issued <= 0;
    end else begin
      if (scenario < 6) begin
        if (accepted[scenario_port]) sent <= 1;
        if (returned[scenario_port]) begin
          scenario <= scenario + 1;
          sent <= 0;
        end
      end else if (scenario == 6) scenario <= 7;
      else issued <= issued | accepted;
    end
  end
`endif
  reg past_valid = 0;
  reg [3:0] owned = 0, expected_valid = 0;
  reg [127:0] expected_data = 0;
  reg [3:0] expected_fault = 0;
  reg pending = 0;
  reg [1:0] owner = 0, cursor = 0;
  reg [75:0] queued = 0;
  reg reservation = 0;
  reg [31:0] reservation_address = 0;
  reg [31:0] memory [0:WORDS-1];
  reg [3:0] known [0:WORDS-1];
  reg [31:0] sampled = 0;
  reg sampled_known = 0;
  integer i, j, index, chosen;
  reg [3:0] predicted_ready;
  reg eligible;
  wire [31:0] address = queued[75:44];
  wire write = queued[42];
  wire [31:0] operand = queued[41:10];
  wire [3:0] mask = queued[9:6];
  wire [1:0] size = queued[5:4];
  wire [3:0] operation = queued[3:0];
  wire [31:0] word_address = {address[31:2], 2'b0};

  function legal;
    input [1:0] port;
    input [75:0] value;
    reg [31:0] a;
    reg w;
    reg [3:0] m, op, wanted;
    reg [1:0] s;
    reg aligned;
    begin
      a = value[75:44]; w = value[42]; m = value[9:6]; s = value[5:4]; op = value[3:0];
      aligned = (s == 0) || (s == 1 && !a[0]) || (s == 2 && a[1:0] == 0);
      wanted = w ? ((s == 0 ? 4'b0001 : s == 1 ? 4'b0011 : 4'b1111) << a[1:0]) : 0;
      legal = {1'b0, a} >= {1'b0, BASE} && {1'b0, a} < ({1'b0, BASE} + WORDS * 4) && aligned;
      if (op == 0) legal = legal && m == wanted && (port != 0 || (!w && s == 2));
      else legal = legal && port == 1 && op <= 11 && s == 2 &&
        (w == (op != 1)) && (m == (op == 1 ? 0 : 15));
    end
  endfunction

  function [31:0] atomic_value;
    input [3:0] op;
    input [31:0] old_value, value;
    begin
      case (op)
        4: atomic_value = old_value + value;
        5: atomic_value = old_value ^ value;
        6: atomic_value = old_value & value;
        7: atomic_value = old_value | value;
        8: atomic_value = $signed(old_value) < $signed(value) ? old_value : value;
        9: atomic_value = $signed(old_value) > $signed(value) ? old_value : value;
        10: atomic_value = old_value < value ? old_value : value;
        11: atomic_value = old_value > value ? old_value : value;
        default: atomic_value = value;
      endcase
    end
  endfunction

  wire permitted = legal(owner, queued);
  wire sc_success = reservation && reservation_address == word_address && !clearReservation;
  wire commit_write = pending && permitted && write && (operation != 2 || sc_success);
  wire [31:0] new_value = atomic_value(operation, sampled, operand);
  wire [31:0] result = !permitted ? 0 : operation == 2 ? (sc_success ? 0 : 1) :
    operation == 0 && write ? 0 : sampled;
  wire [31:0] memory_index = (address - BASE) >> 2;
  reg previous_lr_stalled = 0, previous_amo_stalled = 0;
  reg [3:0] response_operation [0:3];
  reg [2:0] invalidators = 0;
  reg clear_seen = 0, competing_write_seen = 0;
  wire [21:0] coverGoals;
  assign coverGoals[0] = initialized;
  generate for (genvar op = 1; op <= 11; op = op + 1) begin
    assign coverGoals[op] = initialized && pending && permitted && operation == op;
  end endgenerate
  assign coverGoals[12] = initialized && pending && permitted && operation == 2 && sc_success;
  assign coverGoals[13] = initialized && pending && permitted && operation == 2 && !sc_success;
  assign coverGoals[14] = initialized && pending && !permitted && operation == 2 && reservation;
  assign coverGoals[15] = initialized && pending && operation == 1 && clearReservation;
  assign coverGoals[16] = initialized && pending && operation == 2 && clearReservation;
  generate for (genvar writer = 1; writer < 4; writer = writer + 1) begin
    assign coverGoals[writer+16] = initialized && commit_write && owner == writer && reservation && reservation_address == word_address;
  end endgenerate
  assign coverGoals[20] = initialized && previous_lr_stalled && commit_write && owner == 3;
  assign coverGoals[21] = initialized && previous_amo_stalled && commit_write && owner == 3;
  always @* begin
    predicted_ready = 0;
    chosen = -1;
    index = 0;
    eligible = 0;
    for (integer offset = 0; offset < 4; offset = offset + 1) begin
      index = (cursor + offset) % 4;
      eligible = request_valid[index] && (!expected_valid[index] || response_ready[index]);
      if (!pending && chosen == -1 && eligible) chosen = index;
    end
    if (chosen != -1) predicted_ready[chosen] = 1;
  end

  always @(posedge clock) begin
    past_valid <= 1;
    if (reset) begin
      initialized <= 0;
      init_waiting <= 0;
      init_word <= 0;
      owned <= 0;
      expected_valid <= 0;
      pending <= 0;
      cursor <= 0;
      reservation <= 0;
      invalidators <= 0;
      clear_seen <= 0;
      competing_write_seen <= 0;
      previous_lr_stalled <= 0;
      previous_amo_stalled <= 0;
      for (i = 0; i < WORDS; i = i + 1) begin
        memory[i] <= 0;
        known[i] <= 0;
      end
    end else begin
      if (!initialized) begin
        if (accepted[2]) init_waiting <= 1;
        if (returned[2]) begin
          init_waiting <= 0;
          if (init_word == WORDS - 1) initialized <= 1;
          else init_word <= init_word + 1;
        end
      end
      assert(request_ready == predicted_ready);
      assert(response_valid == expected_valid);
      assert((accepted & (accepted - 1'b1)) == 0);
      assert(formalMask == (commit_write ? mask : 0));
      if (commit_write) begin
        assert(formalAddress == memory_index);
        assert(formalWriteData == new_value);
      end
      if (chosen == -1) assert(!formalRead);
      else begin
        assert(formalRead == legal(chosen, payload[chosen*76 +: 76]));
        if (formalRead) assert(formalAddress == ((payload[chosen*76 + 44 +: 32] - BASE) >> 2));
      end
      for (i = 0; i < WORDS; i = i + 1)
        for (j = 0; j < 4; j = j + 1)
          if (known[i][j]) assert(formalMemory[i*32 + j*8 +: 8] == memory[i][j*8 +: 8]);
      for (i = 0; i < 4; i = i + 1) begin
        if (past_valid && !$past(reset)) begin
          if ($past(request_valid[i] && !request_ready[i]))
            assume(request_valid[i] && $stable(payload[i*76 +: 76]));
          if ($past(response_valid[i] && !response_ready[i])) begin
            assert(response_valid[i]);
            assert($stable({response_fault[i], response_data[i*32 +: 32]}));
          end
        end
        if (response_valid[i]) begin
          assert(owned[i]);
          assert(response_data[i*32 +: 32] == expected_data[i*32 +: 32]);
          assert(response_fault[i] == expected_fault[i]);
        end
        if (returned[i]) begin
          owned[i] <= 0;
          expected_valid[i] <= 0;
        end
        if (accepted[i]) begin
          assert(!owned[i] || returned[i]);
          owned[i] <= 1;
          queued <= payload[i*76 +: 76];
          owner <= i;
          cursor <= (i + 1) % 4;
          pending <= 1;
          if (legal(i, payload[i*76 +: 76])) begin
            sampled <= memory[(payload[i*76 + 44 +: 32] - BASE) >> 2];
            sampled_known <= known[(payload[i*76 + 44 +: 32] - BASE) >> 2] == 15;
          end else begin
            sampled <= 0;
            sampled_known <= 0;
          end
        end
      end
      if (pending) begin
        assert(accepted == 0);
        assert(!expected_valid[owner]);
        assert(owned[owner]);
        pending <= 0;
        expected_valid[owner] <= 1;
        expected_fault[owner] <= !permitted;
        expected_data[owner*32 +: 32] <= result;
        response_operation[owner] <= operation;
        if (permitted && !(operation == 0 && write)) assert(sampled_known);
        if (permitted && sampled_known) assert(formalReadData == sampled);
        if (owner == 1 && operation == 2) reservation <= 0;
        if (permitted && operation == 1) begin
          reservation <= 1;
          reservation_address <= word_address;
        end
        if (commit_write) begin
          for (j = 0; j < 4; j = j + 1) begin
            if (mask[j]) begin
              memory[memory_index][j*8 +: 8] <= new_value[j*8 +: 8];
              known[memory_index][j] <= 1;
            end
          end
          if (reservation && reservation_address == word_address) begin
            reservation <= 0;
            if (owner != 0) invalidators[owner - 1] <= 1;
          end
          if (owner == 3) competing_write_seen <= 1;
        end
      end
      if (clearReservation) begin
        reservation <= 0;
        clear_seen <= 1;
      end
      previous_lr_stalled <= response_valid[1] && !response_ready[1] && response_operation[1] == 1;
      previous_amo_stalled <= response_valid[1] && !response_ready[1] && response_operation[1] >= 3;
`ifndef OWNERSHIP_COVER
      for (i = 0; i < 22; i = i + 1) cover(coverGoals[i]);
`else
      cover(initialized && invalidators == 7 && clear_seen && competing_write_seen);
      cover(initialized && response_valid == 15 && response_ready == 0);
`endif
    end
  end
endmodule
