// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

module rvfi_csr_guard (
    input clock, reset, valid, trap,
    input [31:0] insn, rd_data, cause,
    input [4:0] rd,
    input [1:0] mode,
    input command_valid,
    input [31:0] read_mask, write_mask
);
    wire csr_opcode = insn[6:0] == 7'h73 && insn[13:12] != 0;
    wire [11:0] address = insn[31:20];
    always @(posedge clock) begin
        if (!reset && valid && csr_opcode) begin
            if (address == 12'hfff || mode < address[9:8]) begin
                assert(trap);
                assert(cause == 2);
            end
            if (trap) begin
                assert(!command_valid);
                assert(write_mask == 0 && read_mask == 0);
                assert(rd == 0 && rd_data == 0);
            end
        end
    end
endmodule
