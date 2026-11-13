// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module arbiter_formal(input clock);
  reg reset = 1, past_valid = 0;
  always @(posedge clock) begin reset <= 0; past_valid <= 1; end
  (* anyseq *) reg first_request_valid, second_request_valid, firstDebug;
  (* anyseq *) reg [75:0] first_payload, second_payload;
  (* anyseq *) reg first_response_ready, second_response_ready;
  (* anyseq *) reg output_request_ready, output_response_valid;
  (* anyseq *) reg [31:0] output_response_bits_data;
  (* anyseq *) reg output_response_bits_fault;
  wire first_request_ready, second_request_ready, first_response_valid, second_response_valid;
  wire [31:0] first_response_bits_data, second_response_bits_data;
  wire first_response_bits_fault, second_response_bits_fault;
  wire output_request_valid, output_response_ready, outputDebug;
  wire [31:0] output_request_bits_address, output_request_bits_data;
  wire output_request_bits_machine, output_request_bits_write;
  wire [3:0] output_request_bits_mask, output_request_bits_operation;
  wire [1:0] output_request_bits_size;
  wire [75:0] output_payload = {output_request_bits_address, output_request_bits_machine,
    output_request_bits_write, output_request_bits_data, output_request_bits_mask,
    output_request_bits_size, output_request_bits_operation};
  DitDahE2MemoryArbiter dut (
    .first_request_bits_address(first_payload[75:44]), .first_request_bits_machine(first_payload[43]),
    .first_request_bits_write(first_payload[42]), .first_request_bits_data(first_payload[41:10]),
    .first_request_bits_mask(first_payload[9:6]), .first_request_bits_size(first_payload[5:4]),
    .first_request_bits_operation(first_payload[3:0]),
    .second_request_bits_address(second_payload[75:44]), .second_request_bits_machine(second_payload[43]),
    .second_request_bits_write(second_payload[42]), .second_request_bits_data(second_payload[41:10]),
    .second_request_bits_mask(second_payload[9:6]), .second_request_bits_size(second_payload[5:4]),
    .second_request_bits_operation(second_payload[3:0]), .*);
  reg owned = 0, locked = 0, owner = 0, tag = 0, prefer_second = 0;
  reg stalled = 0;
  reg [76:0] stalled_payload = 0;
  wire selected = owned || locked ? owner :
    (second_request_valid && (!first_request_valid || prefer_second));
  wire source_valid = selected ? second_request_valid : first_request_valid;
  wire take = output_request_valid && output_request_ready;
  wire finish = output_response_valid && output_response_ready;
  wire first_take = first_request_valid && first_request_ready;
  wire second_take = second_request_valid && second_request_ready;
  always @(posedge clock) begin
    if (!reset) begin
      bus_response_owned: assume(!output_response_valid || owned);
      if (past_valid && $past(first_request_valid && !first_request_ready)) begin
        first_source_valid_stable: assume(first_request_valid);
        first_source_payload_stable: assume(first_payload == $past(first_payload));
      end
      if (past_valid && $past(second_request_valid && !second_request_ready)) begin
        second_source_valid_stable: assume(second_request_valid);
        second_source_payload_stable: assume(second_payload == $past(second_payload));
      end
      if (past_valid && $past(output_response_valid && !output_response_ready)) begin
        bus_response_valid_stable: assume(output_response_valid);
        bus_response_data_stable: assume(output_response_bits_data == $past(output_response_bits_data));
        bus_response_fault_stable: assume(output_response_bits_fault == $past(output_response_bits_fault));
      end
      arbiter_single_source_accept: assert(!(first_take && second_take));
      arbiter_exact_request_accept: assert(take == (first_take || second_take));
      arbiter_single_pending: assert(!owned || !output_request_valid);
      arbiter_offer_policy: assert(output_request_valid == (!owned && source_valid));
      if (output_request_valid) begin
        arbiter_payload_owner: assert(output_payload == (selected ? second_payload : first_payload));
        arbiter_offer_tag: assert(outputDebug == (locked ? tag : (selected || firstDebug)));
      end
      if (stalled) begin
        arbiter_stalled_offer_valid: assert(output_request_valid);
        arbiter_stalled_payload_tag: assert({outputDebug, output_payload} == stalled_payload);
      end
      arbiter_first_response_owner: assert(first_response_valid == (owned && !owner && output_response_valid));
      arbiter_second_response_owner: assert(second_response_valid == (owned && owner && output_response_valid));
      arbiter_response_ready_owner: assert(output_response_ready == (owned && (owner ? second_response_ready : first_response_ready)));
      if (owned) arbiter_held_owner_tag: assert(outputDebug == tag);
      if (first_response_valid) begin
        arbiter_first_response_data: assert(first_response_bits_data == output_response_bits_data);
        arbiter_first_response_fault: assert(first_response_bits_fault == output_response_bits_fault);
      end
      if (second_response_valid) begin
        arbiter_second_response_data: assert(second_response_bits_data == output_response_bits_data);
        arbiter_second_response_fault: assert(second_response_bits_fault == output_response_bits_fault);
      end
      cover_first_contention_grant: cover(first_take && second_request_valid);
      cover_second_contention_grant: cover(second_take && first_request_valid);
      cover_stalled_debug_change: cover(stalled && firstDebug != $past(firstDebug));
      cover_first_response_stall: cover(first_response_valid && !first_response_ready);
      cover_second_response_stall: cover(second_response_valid && !second_response_ready);
      cover_first_fault: cover(first_response_valid && first_response_bits_fault);
      cover_second_fault: cover(second_response_valid && second_response_bits_fault);
      cover_round_robin_second: cover(prefer_second && second_take && first_request_valid);
    end
    if (reset) begin
      owned <= 0; locked <= 0; owner <= 0; tag <= 0; prefer_second <= 0;
      stalled <= 0;
    end else begin
      if (!owned && !locked && source_valid) begin
        owner <= selected; tag <= selected || firstDebug;
        locked <= !output_request_ready;
      end
      if (take) begin owned <= 1; locked <= 0; end
      if (finish) begin owned <= 0; locked <= 0; prefer_second <= !owner; end
      stalled <= output_request_valid && !output_request_ready;
      stalled_payload <= {outputDebug, output_payload};
    end
  end
endmodule
