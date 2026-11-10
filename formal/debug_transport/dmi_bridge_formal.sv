// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module dmi_bridge_formal(
  input tck, input clock, input reset,
  input upstream_request_valid, output upstream_request_ready,
  input [6:0] upstream_request_bits_address,
  input [31:0] upstream_request_bits_data,
  input [1:0] upstream_request_bits_op,
  output upstream_response_valid, input upstream_response_ready,
  output [31:0] upstream_response_bits_data,
  output [1:0] upstream_response_bits_status,
  output downstream_request_valid, input downstream_request_ready,
  output [6:0] downstream_request_bits_address,
  output [31:0] downstream_request_bits_data,
  output [1:0] downstream_request_bits_op,
  input downstream_response_valid, output downstream_response_ready,
  input [31:0] downstream_response_bits_data,
  input [1:0] downstream_response_bits_status
);
  DitDahE2DmiBridge dut (.*);

  reg initialized = 0;
  always @($global_clock) begin
    initialized <= 1;
    if (!initialized) initial_common_cold_reset: assume(reset);
    else no_later_cold_reset: assume(!reset);
  end

  reg source_owned = 0, source_epoch = 0;
  reg source_response_stalled = 0, source_completed_once = 0;
  reg source_request_blocked = 0, source_response_blocked = 0;
  reg [40:0] source_request_payload, source_request_hold;
  reg [33:0] source_response_hold;
  reg system_sent_epoch = 0, system_replied_epoch = 0;
  reg system_request_blocked = 0, system_response_blocked = 0;
  reg [40:0] system_request_hold;
  reg [33:0] system_response_payload, system_response_hold;
  wire source_accept = upstream_request_valid && upstream_request_ready;
  wire source_return = upstream_response_valid && upstream_response_ready;
  wire downstream_send = downstream_request_valid && downstream_request_ready;
  wire downstream_reply = downstream_response_valid && downstream_response_ready;
  wire downstream_debt = system_sent_epoch != system_replied_epoch;

  always @(posedge tck or posedge reset) begin
    if (reset) begin
      source_owned <= 0;
      source_epoch <= 0;
      source_response_stalled <= 0;
      source_completed_once <= 0;
      source_request_blocked <= 0;
      source_response_blocked <= 0;
    end else begin
      if (source_request_blocked) begin
        upstream_request_valid_stable: assume(upstream_request_valid);
        upstream_request_payload_stable: assume({upstream_request_bits_address, upstream_request_bits_data, upstream_request_bits_op} == source_request_hold);
      end
      if (source_response_blocked) begin
        upstream_response_valid_stable: assert(upstream_response_valid);
        upstream_response_payload_stable: assert({upstream_response_bits_data, upstream_response_bits_status} == source_response_hold);
      end
      source_request_blocked <= upstream_request_valid && !upstream_request_ready;
      if (upstream_request_valid && !upstream_request_ready)
        source_request_hold <= {upstream_request_bits_address, upstream_request_bits_data, upstream_request_bits_op};
      source_response_blocked <= upstream_response_valid && !upstream_response_ready;
      if (upstream_response_valid && !upstream_response_ready)
        source_response_hold <= {upstream_response_bits_data, upstream_response_bits_status};
      if (source_accept) begin
        upstream_single_outstanding: assert(!source_owned);
        source_owned <= 1;
        source_epoch <= !source_epoch;
        source_request_payload <= {upstream_request_bits_address, upstream_request_bits_data, upstream_request_bits_op};
        source_response_stalled <= 0;
      end
      if (source_owned) upstream_backpressure_while_owned: assert(!upstream_request_ready);
      if (upstream_response_valid) begin
        upstream_response_has_owner: assert(source_owned);
        upstream_response_has_downstream_reply: assert(system_replied_epoch == source_epoch);
        upstream_response_payload: assert({upstream_response_bits_data, upstream_response_bits_status} == system_response_payload);
        if (!upstream_response_ready) source_response_stalled <= 1;
      end
      if (source_return) begin
        source_owned <= 0;
        source_completed_once <= 1;
      end
      cover_upstream_request_backpressure: cover(upstream_request_valid && !upstream_request_ready && source_owned);
      cover_upstream_stalled_error_response: cover(source_return && source_response_stalled && upstream_response_bits_status == 2);
      cover_upstream_second_response: cover(source_return && source_completed_once && !source_epoch);
    end
  end

  always @(posedge clock or posedge reset) begin
    if (reset) begin
      system_sent_epoch <= 0;
      system_replied_epoch <= 0;
      system_request_blocked <= 0;
      system_response_blocked <= 0;
    end else begin
      if (system_request_blocked) begin
        downstream_request_valid_stable: assert(downstream_request_valid);
        downstream_request_payload_stable: assert({downstream_request_bits_address, downstream_request_bits_data, downstream_request_bits_op} == system_request_hold);
      end
      if (system_response_blocked) begin
        downstream_response_valid_stable: assume(downstream_response_valid);
        downstream_response_payload_stable: assume({downstream_response_bits_data, downstream_response_bits_status} == system_response_hold);
      end
      system_request_blocked <= downstream_request_valid && !downstream_request_ready;
      if (downstream_request_valid && !downstream_request_ready)
        system_request_hold <= {downstream_request_bits_address, downstream_request_bits_data, downstream_request_bits_op};
      system_response_blocked <= downstream_response_valid && !downstream_response_ready;
      if (downstream_response_valid && !downstream_response_ready)
        system_response_hold <= {downstream_response_bits_data, downstream_response_bits_status};
      downstream_response_has_request: assume(!downstream_response_valid || downstream_debt || downstream_send);
      downstream_response_ready_only_with_debt: assert(!downstream_response_ready || downstream_debt || downstream_send);
      if (downstream_request_valid) begin
        downstream_request_has_owner: assert(source_owned);
        downstream_request_once: assert(system_sent_epoch != source_epoch);
        downstream_request_payload: assert({downstream_request_bits_address, downstream_request_bits_data, downstream_request_bits_op} == source_request_payload);
      end
      if (downstream_send) system_sent_epoch <= source_epoch;
      if (downstream_reply) begin
        downstream_reply_has_owner: assert(source_owned);
        system_replied_epoch <= source_epoch;
        system_response_payload <= {downstream_response_bits_data, downstream_response_bits_status};
      end
      cover_downstream_stalled_accept: cover(downstream_send && system_request_blocked);
      cover_downstream_zero_latency_reply: cover(downstream_send && downstream_reply);
    end
  end
endmodule
