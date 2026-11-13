// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module debug_sba_formal(input clock);
  reg reset = 1;
  reg past_valid = 0;
  always @(posedge clock) begin reset <= 0; past_valid <= 1; end
  (* anyseq *) reg active, accepted;
  (* anyseq *) reg [6:0] request_address;
  (* anyseq *) reg [1:0] request_op;
  (* anyseq *) reg [31:0] request_data;
  (* anyseq *) reg systemBus_request_ready, systemBus_response_valid;
  (* anyseq *) reg [31:0] systemBus_response_bits_data;
  (* anyseq *) reg systemBus_response_bits_fault;
  wire [31:0] readData;
  wire idle, systemBus_request_valid, systemBus_response_ready;
  wire [31:0] systemBus_request_bits_address, systemBus_request_bits_data;
  wire systemBus_request_bits_machine, systemBus_request_bits_write;
  wire [3:0] systemBus_request_bits_mask, systemBus_request_bits_operation;
  wire [1:0] systemBus_request_bits_size;
  DitDahE2DebugSystemBus dut(.*);
  wire take = systemBus_request_valid && systemBus_request_ready;
  wire finish = systemBus_response_valid && systemBus_response_ready;
  wire [75:0] payload = {systemBus_request_bits_address, systemBus_request_bits_machine,
    systemBus_request_bits_write, systemBus_request_bits_data,
    systemBus_request_bits_mask, systemBus_request_bits_size, systemBus_request_bits_operation};
  reg owned = 0, stalled = 0, cancelled = 0;
  reg [75:0] previous_payload = 0;
  wire [3:0] byte_mask = systemBus_request_bits_size == 0 ? 4'b0001 :
    systemBus_request_bits_size == 1 ? 4'b0011 : 4'b1111;
  always @(posedge clock) begin
    if (!reset) begin
      // The responder owns only accepted requests; delay and data remain arbitrary.
      memory_response_owned: assume(!systemBus_response_valid || owned);
      if (past_valid && $past(systemBus_response_valid && !systemBus_response_ready)) begin
        memory_response_valid_stable: assume(systemBus_response_valid);
        memory_response_data_stable: assume(systemBus_response_bits_data == $past(systemBus_response_bits_data));
        memory_response_fault_stable: assume(systemBus_response_bits_fault == $past(systemBus_response_bits_fault));
      end
      sba_response_owner: assert(systemBus_response_ready == owned);
      sba_single_outstanding: assert(!take || !owned);
      sba_idle_quiet: assert(!idle || (!systemBus_request_valid && !systemBus_response_ready));
      sba_owned_not_idle: assert(!owned || !idle);
      if (stalled) begin
        sba_stalled_offer_valid: assert(systemBus_request_valid);
        sba_stalled_payload_stable: assert(payload == previous_payload);
      end
      if (systemBus_request_valid) begin
        sba_machine_access: assert(systemBus_request_bits_machine);
        sba_ordinary_access: assert(systemBus_request_bits_operation == 0);
        sba_supported_size: assert(systemBus_request_bits_size <= 2);
        sba_halfword_alignment: assert(systemBus_request_bits_size == 0 || !systemBus_request_bits_address[0]);
        sba_word_alignment: assert(systemBus_request_bits_size != 2 || systemBus_request_bits_address[1:0] == 0);
        sba_write_mask: assert(systemBus_request_bits_mask == (systemBus_request_bits_write ?
          (byte_mask << systemBus_request_bits_address[1:0]) : 4'b0000));
      end
      if (!active) sba_inactive_hidden: assert(readData == 0);
      if (active && request_address == 7'h38) begin
        sba_version: assert(readData[31:29] == 1);
        sba_reserved_bits: assert(readData[28:23] == 0);
        sba_busy_status: assert(readData[21] == !idle);
        sba_address_width: assert(readData[11:5] == 32);
        sba_access_capabilities: assert(readData[4:0] == 7);
      end
      cover_byte_lane3: cover(take && systemBus_request_bits_write && systemBus_request_bits_size == 0 && systemBus_request_bits_address[1:0] == 3);
      cover_halfword_lane2: cover(take && systemBus_request_bits_write && systemBus_request_bits_size == 1 && systemBus_request_bits_address[1:0] == 2);
      cover_word_read: cover(take && !systemBus_request_bits_write && systemBus_request_bits_size == 2);
      cover_deactivated_offer: cover(stalled && !active && systemBus_request_valid);
      cover_cancelled_return_new_epoch: cover(finish && cancelled && active);
      cover_busy_conflict: cover(active && request_address == 7'h38 && readData[22]);
      cover_bus_fault: cover(active && request_address == 7'h38 && readData[14:12] == 2);
      cover_alignment_error: cover(active && request_address == 7'h38 && readData[14:12] == 3);
      cover_unsupported_size: cover(active && request_address == 7'h38 && readData[14:12] == 4);
    end
    if (reset) begin
      owned <= 0;
      stalled <= 0;
      cancelled <= 0;
    end else begin
      if (take) owned <= 1;
      if (finish) owned <= 0;
      if (!active && !idle) cancelled <= 1;
      if (finish) cancelled <= 0;
      stalled <= systemBus_request_valid && !systemBus_request_ready;
      previous_payload <= payload;
    end
  end
endmodule
