// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module fetch_latency #(parameter COMPRESSED = 1)(input clock);
  localparam BOUND = COMPRESSED ? 4 : 3;
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyseq *) reg redirect, pause, memory_request_ready, memory_response_valid, output_ready, measure;
  (* anyseq *) reg [31:0] target;
  wire [31:0] memory_response_bits_data = 32'h00130013;
  wire memory_response_bits_fault = 0;
  (* anyseq *) reg machine;
  wire memory_request_bits_machine;
  wire idle, memory_request_valid, memory_request_bits_write, memory_response_ready, output_valid;
  wire [31:0] memory_request_bits_address, memory_request_bits_data, output_bits_pc, output_bits_word;
  wire [3:0] memory_request_bits_mask;
  wire [1:0] memory_request_bits_size;
  wire [2:0] output_bits_length;
  wire output_bits_fault;
  wire [31:0] output_bits_faultAddress;
  DitDahE2Fetch dut (.*);
  reg outstanding = 0, offered = 0, measuring = 0, past_valid = 0;
  reg started_held = 0, started_outstanding = 0;
  reg [2:0] elapsed = 0;
  reg [31:0] selected_pc;
  wire request = memory_request_valid && memory_request_ready;
  wire response = memory_response_valid && memory_response_ready;
  wire arrival = measuring && output_valid && output_ready && output_bits_pc == selected_pc;
  wire fast = measure || measuring;
  always @(posedge clock) begin
    past_valid <= 1;
    assume(COMPRESSED ? target[0] == 0 : target[1:0] == 0);
    assume(!memory_response_valid || outstanding);
    assume(!measure || (redirect && !pause && !measuring));
    assume(!measuring || !redirect);
    if (past_valid && !$past(reset)) begin
      if ($past(pause) && !pause) assume(redirect || $past(redirect));
      if ($past(memory_response_valid && !memory_response_ready)) assume(memory_response_valid);
    end
    if (fast) begin
      assume(!pause && memory_request_ready && output_ready);
      assume(memory_response_valid == outstanding);
    end
    if (reset) begin
      outstanding <= 0;
      offered <= 0;
      measuring <= 0;
      elapsed <= 0;
    end else begin
      if (response) begin
        assert(outstanding);
        outstanding <= 0;
      end
      if (memory_request_valid && !memory_request_ready) offered <= 1;
      if (request) begin
        assert(!outstanding || response);
        outstanding <= 1;
        offered <= 0;
      end
      if (measure) begin
        measuring <= 1;
        elapsed <= 0;
        selected_pc <= target;
        started_held <= offered;
        started_outstanding <= outstanding;
      end
      if (measuring) begin
        assert(!output_valid || output_bits_pc == selected_pc);
        if (elapsed == BOUND - 1) assert(arrival);
        if (arrival) measuring <= 0;
        else elapsed <= elapsed + 1;
      end
      cover(arrival && elapsed == BOUND - 1 && started_held);
      cover(arrival && elapsed == BOUND - 1 && started_outstanding);
      cover(arrival && selected_pc == (COMPRESSED ? 32'hfffffffe : 32'hfffffffc));
    end
  end
endmodule
