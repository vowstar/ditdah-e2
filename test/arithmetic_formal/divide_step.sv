// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

module div_transition #(
    parameter bit SUBTRACT = 1'b0
) (
    input logic clock,
    input logic [31:0] remainder_word,
    input logic [31:0] divisor,
    input logic [30:0] quotient_partial,
    input logic incoming_bit
);
    wire [32:0] shifted = {remainder_word, incoming_bit};
    wire subtraction_defined = shifted >= {1'b0, divisor};
    wire [32:0] next_remainder = SUBTRACT ?
        shifted - {1'b0, divisor} : shifted;
    wire [31:0] next_quotient_partial = {quotient_partial, SUBTRACT};
    wire [64:0] old_sum = {33'd0, remainder_word} +
        ({33'd0, divisor} * {34'd0, quotient_partial});
    wire [64:0] next_sum = {32'd0, next_remainder} +
        ({33'd0, divisor} * {33'd0, next_quotient_partial});
    wire [64:0] doubled_sum_with_bit = (old_sum << 1) + {64'd0, incoming_bit};

    // The subtracting branch is conditional, rather than an input assumption.
    always @(posedge clock) begin
        if (!SUBTRACT || subtraction_defined)
            exact_polynomial_transition: assert(next_sum == doubled_sum_with_bit);
    end
endmodule

module div_transition_nosubtract (
    input logic clock,
    input logic [31:0] remainder_word,
    input logic [31:0] divisor,
    input logic [30:0] quotient_partial,
    input logic incoming_bit
);
    div_transition #(.SUBTRACT(1'b0)) lemma(.*);
endmodule

module div_transition_subtract (
    input logic clock,
    input logic [31:0] remainder_word,
    input logic [31:0] divisor,
    input logic [30:0] quotient_partial,
    input logic incoming_bit
);
    div_transition #(.SUBTRACT(1'b1)) lemma(.*);
endmodule
