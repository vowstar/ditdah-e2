// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module DitDahE2Sram #(
  parameter DEPTH = 1024,
  parameter WIDTH = 32,
  parameter MASK_GRANULARITY = 8,
  parameter READ_LATENCY = 1,
  parameter ADDRESS_WIDTH = DEPTH > 1 ? $clog2(DEPTH) : 1
) (
  input wire clock,
  input wire [ADDRESS_WIDTH-1:0] address,
  input wire readEnable,
  input wire [WIDTH/MASK_GRANULARITY-1:0] writeMask,
  input wire [WIDTH-1:0] writeData,
  output reg [WIDTH-1:0] readData
);
  reg [WIDTH-1:0] memory [0:DEPTH-1];
  wire validAddress = {1'b0, address} < (ADDRESS_WIDTH+1)'(DEPTH);
  generate
    if (DEPTH < 1 || WIDTH < 1 || MASK_GRANULARITY < 1 || MASK_GRANULARITY % 8 != 0 ||
        WIDTH % MASK_GRANULARITY != 0 || (READ_LATENCY != 1 && READ_LATENCY != 2) ||
        ADDRESS_WIDTH < (DEPTH > 1 ? $clog2(DEPTH) : 1)) begin : invalid_geometry
      initial $fatal(1, "Unsupported SRAM geometry or read latency");
    end
    if (READ_LATENCY == 1) begin : read_one
      always @(posedge clock)
        if (readEnable && validAddress) readData <= memory[address];
    end else begin : read_two
      reg pending;
      reg [WIDTH-1:0] sampled;
      always @(posedge clock) begin
        pending <= readEnable && validAddress;
        if (readEnable && validAddress) sampled <= memory[address];
        if (pending) readData <= sampled;
      end
    end
  endgenerate
  // Nonblocking updates preserve the word sampled by a simultaneous read.
  always @(posedge clock)
    for (integer lane = 0; lane < WIDTH/MASK_GRANULARITY; lane = lane + 1)
      if (validAddress && writeMask[lane])
        memory[address][lane*MASK_GRANULARITY +: MASK_GRANULARITY] <=
          writeData[lane*MASK_GRANULARITY +: MASK_GRANULARITY];
endmodule
