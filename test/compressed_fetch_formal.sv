// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module compressed_fetch_formal #(parameter COMPRESSED = 1, parameter [31:0] RESET_PC = 0)(input clock);
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyseq *) reg redirect, pause, memory_request_ready, memory_response_valid, output_ready;
  (* anyseq *) reg [31:0] target, memory_response_bits_data;
  (* anyseq *) reg memory_response_bits_fault;
  (* anyseq *) reg machine;
  wire memory_request_bits_machine;
  wire idle, memory_request_valid, memory_request_bits_write, memory_response_ready, output_valid;
  wire [31:0] memory_request_bits_address, memory_request_bits_data, output_bits_pc, output_bits_word;
  wire [3:0] memory_request_bits_mask, memory_request_bits_operation;
  wire [1:0] memory_request_bits_size;
  wire output_bits_fault;
  wire [2:0] output_bits_length;
  wire [31:0] output_bits_faultAddress;
  wire formal_outstanding, formal_held, formal_held_discarded, formal_discarded, formal_first_valid, formal_second_valid;
  wire formal_first_fault, formal_second_fault;
  wire [31:0] formal_assembly_pc, formal_next_word, formal_first_word, formal_second_word;
  wire [31:0] formal_first_address, formal_second_address, formal_address, formal_held_address;
  DitDahE2Fetch dut (.*);

  reg outstanding = 0, poisoned = 0, canceled_offer = 0, offered = 0;
  reg stream_valid = 1, skip_lower = COMPRESSED && RESET_PC[1], past_valid = 0;
  reg [31:0] accepted_address, expected_request = {RESET_PC[31:2], 2'b0}, expected_pc = RESET_PC;
  reg [3:0] count = 0;
  reg [15:0] parcel [0:5], next_parcel [0:5];
  reg [31:0] parcel_address [0:5], next_address [0:5];
  reg parcel_fault [0:5], next_fault [0:5];
  wire flush = redirect || pause;
  wire request = memory_request_valid && memory_request_ready;
  wire response = memory_response_valid && memory_response_ready;
  wire transfer = output_valid && output_ready;
  wire append = response && !poisoned && !flush;
  wire [3:0] instruction_parcels = COMPRESSED && (parcel_fault[0] || parcel[0][1:0] != 3) ? 1 : 2;
  wire available = count >= instruction_parcels && count != 0;
  wire expected_fault = parcel_fault[0] || (instruction_parcels == 2 && parcel_fault[1]);
  wire [31:0] expected_word = COMPRESSED && expected_fault ? 0 : instruction_parcels == 1 ?
                              {16'b0, parcel[0]} : {parcel[1], parcel[0]};
  wire [31:0] expected_fault_address = parcel_fault[0] ? parcel_address[0] :
                                     expected_fault ? parcel_address[1] : expected_pc;
  wire [3:0] consumed = transfer ? instruction_parcels : 0;
  wire [3:0] remaining = count - consumed;
  wire [3:0] appended = append ? (skip_lower ? 1 : 2) : 0;
  wire [3:0] pending = output_valid ? instruction_parcels : 0;
  wire [31:0] assembly_pc = expected_pc + {27'b0, pending, 1'b0};
  wire [3:0] first_parcels = formal_first_valid ? (assembly_pc[1] ? 1 : 2) : 0;
  wire [3:0] second_index = pending + first_parcels;
  integer i, j;

  // Responses add parcels. Only output transfers consume them.
  always @* begin
    for (i = 0; i < 6; i = i + 1) begin
      next_parcel[i] = i + consumed < 6 ? parcel[i + consumed] : 0;
      next_address[i] = i + consumed < 6 ? parcel_address[i + consumed] : 0;
      next_fault[i] = i + consumed < 6 ? parcel_fault[i + consumed] : 0;
    end
    if (append && remaining < 6) begin
      next_parcel[remaining] = skip_lower ? memory_response_bits_data[31:16] : memory_response_bits_data[15:0];
      next_address[remaining] = accepted_address + (skip_lower ? 2 : 0);
      next_fault[remaining] = memory_response_bits_fault;
      if (!skip_lower && remaining + 1 < 6) begin
        next_parcel[remaining + 1] = memory_response_bits_data[31:16];
        next_address[remaining + 1] = accepted_address + 2;
        next_fault[remaining + 1] = memory_response_bits_fault;
      end
    end
  end

  reg saw_short_lower = 0, saw_fault_lower = 0, saw_blocked_redirect = 0, saw_discard = 0;
  reg [31:0] prior_pc;
  always @(posedge clock) begin
    past_valid <= 1;
    assume(COMPRESSED ? target[0] == 0 : target[1:0] == 0);
    assume(!memory_response_valid || outstanding);
    if (past_valid && !$past(reset)) begin
      if ($past(pause) && !pause) assume(redirect || $past(redirect));
      if ($past(memory_response_valid && !memory_response_ready)) begin
        assume(memory_response_valid);
        assume($stable({memory_response_bits_data, memory_response_bits_fault}));
      end
    end
    if (reset) begin
      outstanding <= 0;
      poisoned <= 0;
      canceled_offer <= 0;
      offered <= 0;
      stream_valid <= 1;
      skip_lower <= COMPRESSED && RESET_PC[1];
      expected_request <= {RESET_PC[31:2], 2'b0};
      expected_pc <= RESET_PC;
      count <= 0;
      saw_short_lower <= 0;
      saw_fault_lower <= 0;
      saw_blocked_redirect <= 0;
      saw_discard <= 0;
      for (j = 0; j < 6; j = j + 1) begin
        parcel[j] <= 0;
        parcel_address[j] <= 0;
        parcel_fault[j] <= 0;
      end
    end else begin
      assert(count <= 6);
      assert(!output_valid || (!flush && stream_valid && available));
      assert(!memory_request_valid || !outstanding || response);
      assert(memory_response_ready == outstanding);
      assert(idle == (!offered && !outstanding && count == 0));
      if (idle && pause) assert(!memory_request_valid && !outstanding && !output_valid);
      assert(memory_request_valid || !canceled_offer);
      if (memory_request_valid) begin
        assert(memory_request_bits_address[1:0] == 0);
        if (!offered) assert(memory_request_bits_machine == machine);
        assert(!memory_request_bits_write && memory_request_bits_data == 0);
        assert(memory_request_bits_mask == 0 && memory_request_bits_size == 2);
        assert(memory_request_bits_operation == 0);
        if (!canceled_offer && stream_valid) assert(memory_request_bits_address == expected_request);
      end
      if (output_valid) begin
        assert(output_bits_pc == expected_pc);
        assert(output_bits_word == expected_word);
        assert(output_bits_length == (instruction_parcels == 1 ? 2 : 4));
        assert(output_bits_fault == expected_fault);
        assert(output_bits_faultAddress == expected_fault_address);
      end
      if (stream_valid && !flush) begin
        for (j = 0; j < 6; j = j + 1)
          if (j < count) assert(parcel_address[j] == expected_pc + 2*j);
      end
      if (past_valid && !$past(reset)) begin
        if ($past(memory_request_valid && !memory_request_ready)) begin
          assert(memory_request_valid);
          assert($stable({memory_request_bits_address, memory_request_bits_write,
                          memory_request_bits_data, memory_request_bits_mask, memory_request_bits_size, memory_request_bits_machine, memory_request_bits_operation}));
        end
        if ($past(output_valid && !output_ready && !flush) && !flush) begin
          assert(output_valid);
          assert($stable({output_bits_pc, output_bits_word, output_bits_length,
                          output_bits_fault, output_bits_faultAddress}));
        end
        if ($past(stream_valid && available && !output_valid && !flush) && !flush)
          assert(output_valid);
      end
      if (memory_request_valid && flush) canceled_offer <= 1;
      if (memory_request_valid && !memory_request_ready) offered <= 1;
      if (response) begin
        assert(outstanding);
        outstanding <= 0;
        if (poisoned) saw_discard <= 1;
      end
      if (flush && outstanding) poisoned <= 1;
      if (request) begin
        assert(!outstanding || response);
        outstanding <= 1;
        accepted_address <= memory_request_bits_address;
        poisoned <= canceled_offer || flush;
        canceled_offer <= 0;
        offered <= 0;
        if (!canceled_offer && !flush && stream_valid) expected_request <= expected_request + 4;
      end
      assert(!append || remaining + appended <= 6);
      count <= remaining + appended;
      for (j = 0; j < 6; j = j + 1) begin
        parcel[j] <= next_parcel[j];
        parcel_address[j] <= next_address[j];
        parcel_fault[j] <= next_fault[j];
      end
      if (append) skip_lower <= 0;
      if (transfer) begin
        expected_pc <= expected_pc + {27'b0, instruction_parcels, 1'b0};
        saw_short_lower <= output_bits_length == 2 && !output_bits_fault && !output_bits_pc[1];
        saw_fault_lower <= output_bits_length == 2 && output_bits_fault && !output_bits_pc[1];
        prior_pc <= output_bits_pc;
      end
      if (redirect && memory_request_valid && !memory_request_ready) saw_blocked_redirect <= 1;
      if (flush) begin
        count <= 0;
        stream_valid <= 0;
        saw_short_lower <= 0;
        saw_fault_lower <= 0;
      end
      if (redirect) begin
        expected_request <= {target[31:2], 2'b0};
        expected_pc <= target;
        skip_lower <= COMPRESSED && target[1];
        stream_valid <= 1;
      end

`ifdef REFINEMENT
      // These state relations are proved with the interface properties.
      assert(stream_valid || pause || redirect);
      if (!COMPRESSED) begin
        assert(expected_pc[1:0] == 0);
        assert(!count[0] && !skip_lower);
      end
      assert(outstanding == formal_outstanding);
      assert(offered == formal_held);
      assert(!formal_held || (!outstanding && memory_request_valid));
      assert(!formal_second_valid || formal_first_valid);
      assert(!(formal_held || outstanding) || !formal_second_valid);
      assert(canceled_offer == (formal_held && formal_held_discarded));
      if (outstanding) begin
        assert(poisoned == formal_discarded);
        assert(formal_address == accepted_address);
      end
      if (canceled_offer || (outstanding && poisoned)) assert(count == 0);
      if (stream_valid && !flush) begin
        assert(expected_pc[0] == 0 && expected_request[1:0] == 0);
        assert(expected_request == expected_pc + {27'b0, count, 1'b0} +
               (outstanding && !poisoned ? 32'd4 : 0) - (skip_lower ? 32'd2 : 0));
        if (skip_lower) assert(count == 0 && expected_pc[1]);
        if (outstanding && !poisoned) assert(accepted_address == expected_request - 4);
        assert(formal_assembly_pc == assembly_pc);
        assert(formal_next_word == expected_request + (formal_held && !canceled_offer ? 4 : 0));
        if (formal_held && !canceled_offer) assert(formal_held_address == expected_request);
        assert(count == pending + first_parcels + (formal_second_valid ? 2 : 0));
        if (formal_first_valid) begin
          assert(formal_first_address == {assembly_pc[31:2], 2'b0});
          assert(formal_first_fault == parcel_fault[pending]);
          if (assembly_pc[1]) assert(formal_first_word[31:16] == parcel[pending]);
          else begin
            assert(formal_first_word[15:0] == parcel[pending]);
            assert(formal_first_word[31:16] == parcel[pending + 1]);
            assert(formal_first_fault == parcel_fault[pending + 1]);
          end
        end
        if (formal_second_valid) begin
          assert(formal_second_address == {assembly_pc[31:2], 2'b0} + 4);
          assert(formal_second_word == {parcel[second_index + 1], parcel[second_index]});
          assert(formal_second_fault == parcel_fault[second_index]);
          assert(formal_second_fault == parcel_fault[second_index + 1]);
        end
      end
`endif

      if (COMPRESSED) begin
        cover(transfer && saw_short_lower && output_bits_pc == prior_pc + 2 && output_bits_length == 2 && !output_bits_fault);
        cover(transfer && output_bits_pc[1] && output_bits_length == 4 && !output_bits_fault);
        cover(transfer && saw_fault_lower && output_bits_pc == prior_pc + 2 && output_bits_fault && output_bits_length == 2);
        cover(transfer && output_bits_pc[1] && output_bits_length == 2 && output_bits_fault);
        cover(transfer && output_bits_length == 4 && output_bits_fault && output_bits_faultAddress == output_bits_pc + 2);
      end else begin
        cover(transfer && output_bits_fault);
      end
      cover(transfer && !output_bits_pc[1] && output_bits_length == 4 && !output_bits_fault);
      cover(transfer && saw_blocked_redirect && saw_discard && !output_bits_fault);
      cover(count == 6 && output_valid && !output_ready);
      cover(transfer && output_bits_pc == (COMPRESSED ? 32'hfffffffe : 32'hfffffffc) && output_bits_length == 4 && !output_bits_fault);
      cover(request && response);
      cover(memory_request_valid && !memory_request_ready && response);
      cover(request && response && poisoned);
      cover(idle && !flush && memory_request_valid);
      cover(idle && pause && !memory_request_valid);
      cover(idle && redirect && !memory_request_valid);
    end
  end
endmodule
