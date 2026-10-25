// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module protection_formal(input clock);
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyseq *) reg allowed, input_request_valid, input_response_ready, output_request_ready;
  (* anyseq *) reg [31:0] input_request_bits_address, input_request_bits_data;
  (* anyseq *) reg input_request_bits_write, input_request_bits_machine;
  (* anyseq *) reg [3:0] input_request_bits_mask;
  (* anyseq *) reg [1:0] input_request_bits_size;
  (* anyseq *) reg output_response_valid, output_response_bits_fault;
  (* anyseq *) reg [31:0] output_response_bits_data;
  wire input_request_ready, input_response_valid, input_response_bits_fault;
  wire [31:0] input_response_bits_data;
  wire output_request_valid, output_request_bits_write, output_request_bits_machine, output_response_ready;
  wire [31:0] output_request_bits_address, output_request_bits_data;
  wire [3:0] output_request_bits_mask;
  wire [1:0] output_request_bits_size;
  DitDahE2MemoryProtection dut(.*);

  wire [71:0] offered_payload = {input_request_bits_address, input_request_bits_data,
    input_request_bits_write, input_request_bits_mask, input_request_bits_size, input_request_bits_machine};
  wire [71:0] external_payload = {output_request_bits_address, output_request_bits_data,
    output_request_bits_write, output_request_bits_mask, output_request_bits_size, output_request_bits_machine};
  reg occupied = 0, admitted = 0, first_offer = 0, first_permission = 0, past_valid = 0;
  wire permission = first_offer ? first_permission : allowed;
  wire accepted = input_request_valid && input_request_ready;
  wire external_accepted = output_request_valid && output_request_ready;
  wire returned = input_response_valid && input_response_ready;
  wire external_returned = output_response_valid && output_response_ready;
  reg denied_seen = 0, allowed_seen = 0;
  always @(posedge clock) begin
    past_valid <= 1;
    if (reset) begin
      assume(!input_request_valid && !output_response_valid);
      occupied <= 0;
      first_offer <= 0;
      denied_seen <= 0;
      allowed_seen <= 0;
    end else begin
      assume(!output_response_valid || (occupied && admitted));
      if (past_valid && !$past(reset)) begin
        if ($past(input_request_valid && !input_request_ready)) begin
          assume(input_request_valid && $stable(offered_payload));
        end
        if ($past(output_response_valid && !output_response_ready)) begin
          assume(output_response_valid && $stable({output_response_bits_data, output_response_bits_fault}));
        end
        if ($past(output_request_valid && !output_request_ready)) begin
          assert(output_request_valid && $stable(external_payload));
        end
        if ($past(input_response_valid && !input_response_ready)) begin
          assert(input_response_valid && $stable({input_response_bits_data, input_response_bits_fault}));
        end
      end
      assert(!input_response_valid || occupied);
      assert(!output_response_ready || (occupied && admitted && input_response_ready));
      if (occupied && !admitted) begin
        assert(input_response_valid && input_response_bits_fault && input_response_bits_data == 0);
        assert(!output_response_ready);
      end
      if (occupied && admitted) begin
        assert(input_response_valid == output_response_valid);
        if (input_response_valid) begin
          assert(input_response_bits_data == output_response_bits_data);
          assert(input_response_bits_fault == output_response_bits_fault);
        end
      end
      if (output_request_valid) begin
        assert(input_request_valid && permission && external_payload == offered_payload);
        assert(!occupied || returned);
      end
      if (accepted) begin
        assert(!occupied || returned);
        assert(external_accepted == permission);
      end
      assert(!external_accepted || accepted);
      assert(external_returned == (returned && admitted));
      if (input_request_valid && !permission && (!occupied || returned)) assert(input_request_ready);
      if (input_request_valid && !accepted && !first_offer) begin
        first_offer <= 1;
        first_permission <= allowed;
      end
      if (returned) begin
        occupied <= 0;
        if (admitted) allowed_seen <= 1;
        else denied_seen <= 1;
      end
      if (accepted) begin
        occupied <= 1;
        admitted <= permission;
        first_offer <= 0;
      end
      cover(returned && !admitted);
      cover(returned && admitted && output_response_bits_fault);
      cover(returned && admitted && !output_response_bits_fault);
      cover(accepted && returned && permission && !admitted);
      cover(accepted && returned && !permission && admitted);
      cover(accepted && first_offer && permission && !allowed);
      cover(accepted && first_offer && !permission && allowed);
      cover(first_offer && occupied && !permission);
      cover(output_request_valid && !output_request_ready && input_request_bits_machine);
      cover(output_request_valid && !output_request_ready && !input_request_bits_machine);
      cover(allowed_seen && denied_seen && !occupied);
    end
  end
endmodule
