// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

// This peer restricts the program, but neither 32-bit arithmetic operand.
module rvfi_m_memory #(parameter DATA = 0) (
    input clock, reset,
    input request_valid,
    output request_ready,
    input [31:0] request_address,
    input request_write,
    input [31:0] request_data,
    input [3:0] request_mask,
    input [1:0] request_size,
    output response_valid,
    input response_ready,
    output [31:0] response_data,
    output response_fault,
    output bus_valid,
    output [31:0] bus_addr,
    output [3:0] bus_rmask, bus_wmask,
    output [31:0] bus_rdata, bus_wdata,
    output bus_fault,
    output [31:0] operand_left, operand_right
);
    (* anyconst *) reg [31:0] left, right;
    (* anyseq *) reg offer_ready;
    reg busy = 0;
    reg [31:0] data;
    reg [31:0] selected;
    assign operand_left = left;
    assign operand_right = right;
    always @* begin
        if (DATA) begin
            case (request_address)
                32'h100: selected = left;
                32'h104: selected = right;
                default: selected = 0;
            endcase
        end else begin
            case (request_address)
                0: selected = 32'h10002083; // lw x1, 0x100(x0)
                4: selected = 32'h10402103; // lw x2, 0x104(x0)
                8: selected = `DITDAH_E2_RVFI_M_INSN;
                default: selected = 32'h0000006f; // jal x0, 0
            endcase
        end
    end
    assign request_ready = !busy && offer_ready;
    assign response_valid = busy;
    assign response_data = data;
    assign response_fault = 0;
    assign bus_valid = request_valid && request_ready;
    assign bus_addr = request_address & 32'hfffffffc;
    assign bus_rmask = request_write ? 0 : 4'b1111;
    assign bus_wmask = request_write ? request_mask : 0;
    assign bus_rdata = selected;
    assign bus_wdata = request_data;
    assign bus_fault = 0;
    always @(posedge clock) begin
        if (reset) busy <= 0;
        else begin
            if (response_valid && response_ready) busy <= 0;
            if (bus_valid) begin
                busy <= 1;
                data <= selected;
            end
        end
    end
endmodule
