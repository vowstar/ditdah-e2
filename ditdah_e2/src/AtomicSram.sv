// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module DitDahE2AtomicSram #(
  parameter WORDS = 1024,
  parameter ADDRESS_WIDTH = 10
) (
  input wire clock,
  input wire [ADDRESS_WIDTH-1:0] address,
  input wire readEnable,
  input wire [3:0] writeMask,
  input wire [31:0] writeData,
  output reg [31:0] readData
);
  reg [31:0] memory [0:WORDS-1];
  always @(posedge clock) begin
    if (readEnable) readData <= memory[address];
    for (integer lane = 0; lane < 4; lane = lane + 1)
      if (writeMask[lane]) memory[address][lane*8 +: 8] <= writeData[lane*8 +: 8];
  end
endmodule
