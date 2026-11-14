// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module DitDahE2AtomicSram #(
  parameter WORDS = 1024,
  parameter ADDRESS_WIDTH = 10,
  parameter READ_LATENCY = 1
) (
  input wire clock,
  input wire [ADDRESS_WIDTH-1:0] address,
  input wire readEnable,
  input wire [3:0] writeMask,
  input wire [31:0] writeData,
  output wire [31:0] readData
);
  DitDahE2Sram #(.DEPTH(WORDS), .WIDTH(32), .MASK_GRANULARITY(8),
    .READ_LATENCY(READ_LATENCY), .ADDRESS_WIDTH(ADDRESS_WIDTH)) storage (
    .clock(clock), .address(address), .readEnable(readEnable),
    .writeMask(writeMask), .writeData(writeData), .readData(readData)
  );
endmodule
