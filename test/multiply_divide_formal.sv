// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module multiply_divide_formal(input clock);
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyseq *) reg cancel, request_valid, response_ready;
  (* anyseq *) reg [2:0] request_bits_operation;
  (* anyseq *) reg [31:0] request_bits_left, request_bits_right;
  wire request_ready, response_valid;
  wire [31:0] response_bits;
  DitDahE2MultiplyDivide dut(.*);

  reg past_valid = 0, pending = 0, seen = 0, completed_once = 0, second = 0;
  reg [5:0] age = 0;
  reg [2:0] held = 0;
  wire accepted = request_valid && request_ready;
  wire completed = response_valid && response_ready;

  always @(posedge clock) begin
    past_valid <= 1;
    if (reset) begin
      pending <= 0;
      seen <= 0;
      age <= 0;
      held <= 0;
      completed_once <= 0;
      second <= 0;
    end else begin
      if (past_valid && !$past(reset) && $past(request_valid && !request_ready)) begin
        assume (request_valid);
        assume ($stable({request_bits_operation, request_bits_left, request_bits_right}));
      end
      if (cancel) begin
        assert (!request_ready && !response_valid);
        pending <= 0;
        seen <= 0;
        held <= 0;
      end else begin
        if (accepted) begin
          assert (!pending);
          pending <= 1;
          seen <= 0;
          age <= 1;
          held <= 0;
          second <= completed_once;
        end
        if (response_valid) begin
          assert (pending);
          seen <= 1;
          if (!response_ready && held != 7) held <= held + 1;
        end
        if (pending && !seen) begin
          assert (age <= 34);
          if (age == 34) assert (response_valid);
          if (!response_valid) age <= age + 1;
        end
        if (completed) begin
          pending <= 0;
          seen <= 0;
          held <= 0;
          completed_once <= 1;
        end
        if (past_valid && !$past(reset) && $past(response_valid && !response_ready)) begin
          assert (response_valid);
`ifdef CHECK_STABILITY
          assert ($stable(response_bits));
`endif
        end
      end
      cover (accepted);
      cover (pending && cancel && age == 17 && !seen);
      cover (pending && cancel && age == 34 && !seen);
      cover (pending && cancel && seen && held >= 3);
      cover (completed && held >= 3);
      cover (completed && second);
    end
  end
endmodule
