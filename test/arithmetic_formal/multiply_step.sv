// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

module mul_transition #(
    parameter bit LOW_BIT = 1'b0
) (
    input logic clock,
    input logic [63:0] accumulator,
    input logic [63:0] multiplicand,
    input logic [30:0] remaining_high
);
    wire [31:0] multiplier = {remaining_high, LOW_BIT};
    wire [31:0] next_multiplier = {1'b0, remaining_high};
    wire [63:0] next_multiplicand = {multiplicand[62:0], 1'b0};
    wire [63:0] next_accumulator = accumulator + (LOW_BIT ? multiplicand : 64'd0);
    wire [63:0] remaining_product = multiplicand * {32'd0, multiplier};
    wire [63:0] next_remaining_product = next_multiplicand * {32'd0, next_multiplier};
    wire [63:0] before_total = accumulator + remaining_product;
    wire [63:0] after_total = next_accumulator + next_remaining_product;

    // Every expression is unsigned and equality is modulo 2^64.
    always @(posedge clock) begin
        exact_polynomial_transition: assert(after_total == before_total);
    end
endmodule

module mul_transition_lsb0 (
    input logic clock,
    input logic [63:0] accumulator,
    input logic [63:0] multiplicand,
    input logic [30:0] remaining_high
);
    mul_transition #(.LOW_BIT(1'b0)) lemma(.*);
endmodule

module mul_transition_lsb1 (
    input logic clock,
    input logic [63:0] accumulator,
    input logic [63:0] multiplicand,
    input logic [30:0] remaining_high
);
    mul_transition #(.LOW_BIT(1'b1)) lemma(.*);
endmodule
