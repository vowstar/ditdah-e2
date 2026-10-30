// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

    function automatic logic [31:0] m_reference (
        input logic [2:0] operation,
        input logic [31:0] left,
        input logic [31:0] right
    );
        logic [63:0] unsigned_product;
        logic signed [63:0] signed_left, signed_right, unsigned_right;
        logic signed [63:0] signed_product, mixed_product;
        logic signed [31:0] left_signed, right_signed;
        begin
            unsigned_product = {32'b0, left} * {32'b0, right};
            signed_left = {{32{left[31]}}, left};
            signed_right = {{32{right[31]}}, right};
            unsigned_right = {32'b0, right};
            signed_product = signed_left * signed_right;
            mixed_product = signed_left * unsigned_right;
            left_signed = left;
            right_signed = right;
            case (operation)
                3'd0: m_reference = unsigned_product[31:0];
                3'd1: m_reference = signed_product[63:32];
                3'd2: m_reference = mixed_product[63:32];
                3'd3: m_reference = unsigned_product[63:32];
                3'd4: begin
                    if (right == 0)
                        m_reference = 32'hffffffff;
                    else if (left == 32'h80000000 && right == 32'hffffffff)
                        m_reference = 32'h80000000;
                    else
                        m_reference = left_signed / right_signed;
                end
                3'd5: m_reference = right == 0 ? 32'hffffffff : left / right;
                3'd6: begin
                    if (right == 0)
                        m_reference = left;
                    else if (left == 32'h80000000 && right == 32'hffffffff)
                        m_reference = 0;
                    else
                        m_reference = left_signed % right_signed;
                end
                3'd7: m_reference = right == 0 ? left : left % right;
            endcase
        end
    endfunction
