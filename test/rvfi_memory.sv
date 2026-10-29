// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

module rvfi_memory (
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
    output bus_fault
);
    (* anyseq *) reg offer_ready;
    (* anyseq *) reg [31:0] next_data;
    (* anyseq *) reg next_fault;
    (* anyseq *) reg [1:0] next_delay;
    reg busy = 0;
    reg [1:0] delay = 0;
    reg [31:0] data;
    reg fault;
`ifdef RISCV_FORMAL_FAIRNESS
    wire available = 1'b1;
`else
    wire available = offer_ready;
`endif
`ifdef DITDAH_E2_RVFI_FAULTS
    wire selected_fault = next_fault;
`else
    wire selected_fault = 1'b0;
`endif
    assign request_ready = !busy && available;
    assign response_valid = busy && delay == 0;
    assign response_data = data;
    assign response_fault = fault;
    assign bus_valid = request_valid && request_ready;
    assign bus_addr = request_address & 32'hfffffffc;
    wire [3:0] read_mask = request_size == 0 ? 4'b0001 :
                           request_size == 1 ? 4'b0011 : 4'b1111;
    assign bus_rmask = request_write ? 0 : read_mask << request_address[1:0];
    assign bus_wmask = request_write ? request_mask : 0;
    assign bus_rdata = next_data;
    assign bus_wdata = request_data;
    assign bus_fault = selected_fault;
    always @(posedge clock) begin
        if (reset) begin
            busy <= 0;
            delay <= 0;
        end else begin
            if (busy && delay != 0) delay <= delay - 1;
            if (response_valid && response_ready) busy <= 0;
            if (bus_valid) begin
                busy <= 1;
                delay <= next_delay;
                data <= next_data;
                fault <= selected_fault;
            end
        end
    end
endmodule
