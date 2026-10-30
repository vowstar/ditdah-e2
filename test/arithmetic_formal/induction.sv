// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module boolean_induction_rule(input logic clock, reset, I);
    logic first_frame = 1'b1;
    logic previous_I = 1'b1;
    always @(posedge clock) begin
        if (reset) begin
            first_frame <= 1'b1;
            previous_I <= 1'b1;
        end else begin
            first_frame <= 1'b0;
            previous_I <= I;
        end
        if (!reset) begin
            base_obligation: assume (!first_frame || I);
            step_obligation: assume (first_frame || !previous_I || I);
            rule_conclusion: assert (I);
            base_is_satisfiable: cover (first_frame && I);
            step_is_satisfiable: cover (!first_frame && previous_I && I);
        end
    end
endmodule
