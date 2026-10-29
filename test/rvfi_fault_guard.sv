// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

module rvfi_fault_guard (
    input clock, reset, valid, trap, mem_fault,
    input [3:0] fault_rmask, fault_wmask, normal_rmask, normal_wmask,
    input [31:0] insn, cause, rd_data,
    input [4:0] rd,
    input command_valid,
    input [31:0] csr_read_mask, csr_write_mask
);
    wire typed_ifetch_fault = mem_fault && !(|fault_rmask) && !(|fault_wmask);
    always @(posedge clock) if (!reset && valid && typed_ifetch_fault) begin
        assert(trap);
        assert(cause == 1);
        assert(insn == 0);
        assert(rd == 0 && rd_data == 0);
        assert(normal_rmask == 0 && normal_wmask == 0);
        assert(!command_valid && csr_read_mask == 0 && csr_write_mask == 0);
    end
endmodule
