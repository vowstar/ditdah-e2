// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module fetch_formal(input clock);
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyseq *) reg redirect, halt, memory_request_ready, memory_response_valid, output_ready;
  (* anyseq *) reg [31:0] target, memory_response_bits_data;
  (* anyseq *) reg memory_response_bits_fault;
  wire idle, memory_request_valid, memory_request_bits_write, memory_response_ready, output_valid;
  wire [31:0] memory_request_bits_address, memory_request_bits_data, output_bits_pc, output_bits_word;
  wire [3:0] memory_request_bits_mask;
  wire [1:0] memory_request_bits_size;
  wire output_bits_fault;
  wire formal_active, formal_sent, formal_discarded, formal_buffered;
  wire [31:0] formal_next_pc;
  DitDahE2Fetch dut (.*);

  reg outstanding = 0, poisoned = 0, expected = 0, canceled_offer = 0;
  reg [31:0] accepted_pc, expected_pc, expected_word;
  reg expected_fault;
  reg past_valid = 0;
  wire request = memory_request_valid && memory_request_ready;
  wire response = memory_response_valid && memory_response_ready;
  wire flush = redirect || halt;
  reg saw_blocked_redirect = 0, saw_poison_drain = 0;
  always @(posedge clock) begin
    past_valid <= 1;
    assume(target[1:0] == 0);
    assume(!memory_response_valid || outstanding);
    if (past_valid && $past(memory_response_valid && !memory_response_ready)) begin
      assume(memory_response_valid);
      assume($stable(memory_response_bits_data));
      assume($stable(memory_response_bits_fault));
    end
    if (reset) begin
      outstanding <= 0;
      poisoned <= 0;
      expected <= 0;
      canceled_offer <= 0;
    end else begin
      // These strengthening invariants are proved, never assumed.
      assert(outstanding == (formal_active && formal_sent));
      assert(expected == formal_buffered);
      assert(formal_next_pc[1:0] == 0);
      assert(memory_request_valid || !canceled_offer);
      if (memory_request_valid) assert(canceled_offer == formal_discarded);
      if (outstanding) assert(poisoned == formal_discarded);
      if (memory_request_valid && flush) canceled_offer <= 1;
      if (request) begin
        assert(!outstanding);
        outstanding <= 1;
        accepted_pc <= memory_request_bits_address;
        poisoned <= flush || canceled_offer;
        canceled_offer <= 0;
      end
      if (flush && outstanding) poisoned <= 1;
      if (output_valid && output_ready) expected <= 0;
      if (response) begin
        assert(outstanding);
        outstanding <= 0;
        if (!poisoned && !flush) begin
          assert(!expected || (output_valid && output_ready));
          expected <= 1;
          expected_pc <= accepted_pc;
          expected_word <= memory_response_bits_data;
          expected_fault <= memory_response_bits_fault;
        end
      end
      if (flush) expected <= 0;
      assert(!memory_request_valid || !outstanding);
      if (outstanding) assert(memory_request_bits_address == accepted_pc);
      assert(!memory_response_ready || outstanding);
      assert(!idle || (!outstanding && !expected));
      assert(output_valid == (expected && !flush));
      if (expected) begin
        assert(output_bits_pc == expected_pc);
        assert(output_bits_word == expected_word);
        assert(output_bits_fault == expected_fault);
      end
      if (memory_request_valid) begin
        assert(memory_request_bits_address[1:0] == 0);
        assert(!memory_request_bits_write && memory_request_bits_mask == 0);
        assert(memory_request_bits_size == 2);
      end
      if (past_valid && !$past(reset) && $past(memory_request_valid && !memory_request_ready)) begin
        assert(memory_request_valid);
        assert($stable(memory_request_bits_address));
      end
      if (redirect && memory_request_valid && !memory_request_ready) saw_blocked_redirect <= 1;
      if (response && poisoned) saw_poison_drain <= 1;
      cover(saw_blocked_redirect && saw_poison_drain && output_valid && output_ready);
      cover(output_valid && output_ready && output_bits_fault);
      cover(expected && flush);
    end
  end
endmodule
