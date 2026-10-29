// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

module rvfi_wrapper (
    input clock, reset,
    `RVFI_OUTPUTS
    `RVFI_BUS_OUTPUTS
);
`ifdef DITDAH_E2_RVFI_IRQ
    (* anyseq *) reg irq_software, irq_timer, irq_external;
`else
    wire irq_software = 0, irq_timer = 0, irq_external = 0;
`endif
    reg [63:0] time_value = 0;
    always @(posedge clock) if (reset) time_value <= 0; else time_value <= time_value + 1;
    wire interrupt_valid;
    wire retire_valid;
    wire [63:0] retire_order;
    wire [2:0] retire_length;
    wire [31:0] retire_insn;
    wire retire_intr;
    wire retire_userMode;
    wire [31:0] retire_pc;
    wire [31:0] retire_nextPc;
    wire [4:0] retire_rd;
    wire retire_writes;
    wire [31:0] retire_value;
    wire retire_trap;
    wire [31:0] retire_cause;
    wire [4:0] retire_rs1;
    wire [31:0] retire_rs1Data;
    wire [4:0] retire_rs2;
    wire [31:0] retire_rs2Data;
    wire [31:0] retire_memoryAddress;
    wire [3:0] retire_memoryReadMask;
    wire [3:0] retire_memoryWriteMask;
    wire [31:0] retire_memoryReadData;
    wire [31:0] retire_memoryWriteData;
    wire retire_memoryFault;
    wire [3:0] retire_faultReadMask;
    wire [3:0] retire_faultWriteMask;
    wire [31:0] retire_misa;
    wire [63:0] retire_csrTime;
    wire retire_csr_valid;
    wire [11:0] retire_csr_address;
    wire [31:0] retire_csr_readMask;
    wire [31:0] retire_csr_writeMask;
    wire [31:0] retire_csr_readData;
    wire [31:0] retire_csr_writeData;
    wire [31:0] retire_csrMstatus_before;
    wire [31:0] retire_csrMstatus_after;
    wire [31:0] retire_csrMstatus_writeMask;
    wire [31:0] retire_csrMepc_before;
    wire [31:0] retire_csrMepc_after;
    wire [31:0] retire_csrMepc_writeMask;
    wire [31:0] retire_csrMcause_before;
    wire [31:0] retire_csrMcause_after;
    wire [31:0] retire_csrMcause_writeMask;
    wire [31:0] retire_csrMtval_before;
    wire [31:0] retire_csrMtval_after;
    wire [31:0] retire_csrMtval_writeMask;
    wire [63:0] retire_csrCycle_before;
    wire [63:0] retire_csrCycle_after;
    wire [63:0] retire_csrCycle_writeMask;
    wire [63:0] retire_csrInstret_before;
    wire [63:0] retire_csrInstret_after;
    wire [63:0] retire_csrInstret_writeMask;
    wire instruction_request_valid;
    wire instruction_request_ready;
    wire [31:0] instruction_request_bits_address;
    wire instruction_request_bits_machine;
    wire instruction_request_bits_write;
    wire [31:0] instruction_request_bits_data;
    wire [3:0] instruction_request_bits_mask;
    wire [1:0] instruction_request_bits_size;
    wire [3:0] instruction_request_bits_operation;
    wire instruction_response_valid;
    wire instruction_response_ready;
    wire [31:0] instruction_response_bits_data;
    wire instruction_response_bits_fault;
    wire data_request_valid;
    wire data_request_ready;
    wire [31:0] data_request_bits_address;
    wire data_request_bits_machine;
    wire data_request_bits_write;
    wire [31:0] data_request_bits_data;
    wire [3:0] data_request_bits_mask;
    wire [1:0] data_request_bits_size;
    wire [3:0] data_request_bits_operation;
    wire data_response_valid;
    wire data_response_ready;
    wire [31:0] data_response_bits_data;
    wire data_response_bits_fault;
    DitDahE2 core (
        .clock(clock),
        .reset(reset),
        .interrupts_software(irq_software),
        .interrupts_timer(irq_timer),
        .interrupts_external(irq_external),
        .timeValue(time_value),
        .interrupt_valid(interrupt_valid),
        .instruction_request_valid(instruction_request_valid),
        .instruction_request_ready(instruction_request_ready),
        .instruction_request_bits_address(instruction_request_bits_address),
        .instruction_request_bits_machine(instruction_request_bits_machine),
        .instruction_request_bits_write(instruction_request_bits_write),
        .instruction_request_bits_data(instruction_request_bits_data),
        .instruction_request_bits_mask(instruction_request_bits_mask),
        .instruction_request_bits_size(instruction_request_bits_size),
        .instruction_request_bits_operation(instruction_request_bits_operation),
        .instruction_response_valid(instruction_response_valid),
        .instruction_response_ready(instruction_response_ready),
        .instruction_response_bits_data(instruction_response_bits_data),
        .instruction_response_bits_fault(instruction_response_bits_fault),
        .data_request_valid(data_request_valid),
        .data_request_ready(data_request_ready),
        .data_request_bits_address(data_request_bits_address),
        .data_request_bits_machine(data_request_bits_machine),
        .data_request_bits_write(data_request_bits_write),
        .data_request_bits_data(data_request_bits_data),
        .data_request_bits_mask(data_request_bits_mask),
        .data_request_bits_size(data_request_bits_size),
        .data_request_bits_operation(data_request_bits_operation),
        .data_response_valid(data_response_valid),
        .data_response_ready(data_response_ready),
        .data_response_bits_data(data_response_bits_data),
        .data_response_bits_fault(data_response_bits_fault),
        .retire_valid(retire_valid),
        .retire_order(retire_order),
        .retire_length(retire_length),
        .retire_insn(retire_insn),
        .retire_intr(retire_intr),
        .retire_userMode(retire_userMode),
        .retire_pc(retire_pc),
        .retire_nextPc(retire_nextPc),
        .retire_rd(retire_rd),
        .retire_writes(retire_writes),
        .retire_value(retire_value),
        .retire_trap(retire_trap),
        .retire_cause(retire_cause),
        .retire_rs1(retire_rs1),
        .retire_rs1Data(retire_rs1Data),
        .retire_rs2(retire_rs2),
        .retire_rs2Data(retire_rs2Data),
        .retire_memoryAddress(retire_memoryAddress),
        .retire_memoryReadMask(retire_memoryReadMask),
        .retire_memoryWriteMask(retire_memoryWriteMask),
        .retire_memoryReadData(retire_memoryReadData),
        .retire_memoryWriteData(retire_memoryWriteData),
        .retire_memoryFault(retire_memoryFault),
        .retire_faultReadMask(retire_faultReadMask),
        .retire_faultWriteMask(retire_faultWriteMask),
        .retire_misa(retire_misa),
        .retire_csrTime(retire_csrTime),
        .retire_csr_valid(retire_csr_valid),
        .retire_csr_address(retire_csr_address),
        .retire_csr_readMask(retire_csr_readMask),
        .retire_csr_writeMask(retire_csr_writeMask),
        .retire_csr_readData(retire_csr_readData),
        .retire_csr_writeData(retire_csr_writeData),
        .retire_csrMstatus_before(retire_csrMstatus_before),
        .retire_csrMstatus_after(retire_csrMstatus_after),
        .retire_csrMstatus_writeMask(retire_csrMstatus_writeMask),
        .retire_csrMepc_before(retire_csrMepc_before),
        .retire_csrMepc_after(retire_csrMepc_after),
        .retire_csrMepc_writeMask(retire_csrMepc_writeMask),
        .retire_csrMcause_before(retire_csrMcause_before),
        .retire_csrMcause_after(retire_csrMcause_after),
        .retire_csrMcause_writeMask(retire_csrMcause_writeMask),
        .retire_csrMtval_before(retire_csrMtval_before),
        .retire_csrMtval_after(retire_csrMtval_after),
        .retire_csrMtval_writeMask(retire_csrMtval_writeMask),
        .retire_csrCycle_before(retire_csrCycle_before),
        .retire_csrCycle_after(retire_csrCycle_after),
        .retire_csrCycle_writeMask(retire_csrCycle_writeMask),
        .retire_csrInstret_before(retire_csrInstret_before),
        .retire_csrInstret_after(retire_csrInstret_after),
        .retire_csrInstret_writeMask(retire_csrInstret_writeMask)
    );

    wire instruction_bus_valid, instruction_bus_fault;
    wire [31:0] instruction_bus_addr, instruction_bus_rdata, instruction_bus_wdata;
    wire [3:0] instruction_bus_rmask, instruction_bus_wmask;
    rvfi_memory instruction_peer (
        .clock(clock),
        .reset(reset),
        .request_valid(instruction_request_valid),
        .request_ready(instruction_request_ready),
        .response_valid(instruction_response_valid),
        .response_ready(instruction_response_ready),
        .response_data(instruction_response_bits_data),
        .response_fault(instruction_response_bits_fault),
        .request_address(instruction_request_bits_address),
        .request_write(instruction_request_bits_write),
        .request_data(instruction_request_bits_data),
        .request_mask(instruction_request_bits_mask),
        .request_size(instruction_request_bits_size),
        .bus_valid(instruction_bus_valid),
        .bus_fault(instruction_bus_fault),
        .bus_addr(instruction_bus_addr),
        .bus_rmask(instruction_bus_rmask),
        .bus_wmask(instruction_bus_wmask),
        .bus_rdata(instruction_bus_rdata),
        .bus_wdata(instruction_bus_wdata)
    );

    wire data_bus_valid, data_bus_fault;
    wire [31:0] data_bus_addr, data_bus_rdata, data_bus_wdata;
    wire [3:0] data_bus_rmask, data_bus_wmask;
    rvfi_memory data_peer (
        .clock(clock),
        .reset(reset),
        .request_valid(data_request_valid),
        .request_ready(data_request_ready),
        .response_valid(data_response_valid),
        .response_ready(data_response_ready),
        .response_data(data_response_bits_data),
        .response_fault(data_response_bits_fault),
        .request_address(data_request_bits_address),
        .request_write(data_request_bits_write),
        .request_data(data_request_bits_data),
        .request_mask(data_request_bits_mask),
        .request_size(data_request_bits_size),
        .bus_valid(data_bus_valid),
        .bus_fault(data_bus_fault),
        .bus_addr(data_bus_addr),
        .bus_rmask(data_bus_rmask),
        .bus_wmask(data_bus_wmask),
        .bus_rdata(data_bus_rdata),
        .bus_wdata(data_bus_wdata)
    );

    assign rvfi_valid = retire_valid;
    assign rvfi_order = retire_order;
    assign rvfi_insn = retire_insn;
    assign rvfi_trap = retire_trap;
    assign rvfi_halt = 1'b0;
    assign rvfi_intr = retire_intr;
    assign rvfi_mode = retire_userMode ? 2'b00 : 2'b11;
    assign rvfi_ixl = 2'b01;
    assign rvfi_rs1_addr = retire_rs1;
    assign rvfi_rs2_addr = retire_rs2;
    assign rvfi_rs1_rdata = retire_rs1Data;
    assign rvfi_rs2_rdata = retire_rs2Data;
    assign rvfi_rd_addr = retire_writes ? retire_rd : 5'b0;
    assign rvfi_rd_wdata = retire_writes ? retire_value : 32'b0;
    assign rvfi_pc_rdata = retire_pc;
    assign rvfi_pc_wdata = retire_nextPc;
    assign rvfi_mem_addr = retire_memoryAddress;
    assign rvfi_mem_rmask = retire_memoryReadMask;
    assign rvfi_mem_wmask = retire_memoryWriteMask;
    assign rvfi_mem_rdata = retire_memoryReadData;
    assign rvfi_mem_wdata = retire_memoryWriteData;
`ifdef RISCV_FORMAL_MEM_FAULT
    assign rvfi_mem_fault = retire_memoryFault;
    assign rvfi_mem_fault_rmask = retire_faultReadMask;
    assign rvfi_mem_fault_wmask = retire_faultWriteMask;
`endif
`ifdef RISCV_FORMAL_BUS
    assign rvfi_bus_valid = {data_bus_valid, instruction_bus_valid};
    assign rvfi_bus_fault = {data_bus_fault, instruction_bus_fault};
    assign rvfi_bus_addr = {data_bus_addr, instruction_bus_addr};
    assign rvfi_bus_rmask = {data_bus_rmask, instruction_bus_rmask};
    assign rvfi_bus_wmask = {data_bus_wmask, instruction_bus_wmask};
    assign rvfi_bus_rdata = {data_bus_rdata, instruction_bus_rdata};
    assign rvfi_bus_wdata = {data_bus_wdata, instruction_bus_wdata};
    assign rvfi_bus_insn = 2'b01;
    assign rvfi_bus_data = 2'b10;
`endif
`ifdef RISCV_FORMAL_CSR_MSTATUS
    assign rvfi_csr_mstatus_rmask = retire_valid ? 32'hffffffff : 0;
    assign rvfi_csr_mstatus_rdata = retire_csrMstatus_before;
    assign rvfi_csr_mstatus_wdata = retire_csrMstatus_after;
    assign rvfi_csr_mstatus_wmask = retire_csrMstatus_writeMask;
`endif
`ifdef RISCV_FORMAL_CSR_MEPC
    assign rvfi_csr_mepc_rmask = retire_valid ? 32'hffffffff : 0;
    assign rvfi_csr_mepc_rdata = retire_csrMepc_before;
    assign rvfi_csr_mepc_wdata = retire_csrMepc_after;
    assign rvfi_csr_mepc_wmask = retire_csrMepc_writeMask;
`endif
`ifdef RISCV_FORMAL_CSR_MCAUSE
    assign rvfi_csr_mcause_rmask = retire_valid ? 32'hffffffff : 0;
    assign rvfi_csr_mcause_rdata = retire_csrMcause_before;
    assign rvfi_csr_mcause_wdata = retire_csrMcause_after;
    assign rvfi_csr_mcause_wmask = retire_csrMcause_writeMask;
`endif
`ifdef RISCV_FORMAL_CSR_MTVAL
    assign rvfi_csr_mtval_rmask = retire_valid ? 32'hffffffff : 0;
    assign rvfi_csr_mtval_rdata = retire_csrMtval_before;
    assign rvfi_csr_mtval_wdata = retire_csrMtval_after;
    assign rvfi_csr_mtval_wmask = retire_csrMtval_writeMask;
`endif
`ifdef RISCV_FORMAL_CSR_MCYCLE
    assign rvfi_csr_mcycle_rmask = retire_valid ? 64'hffffffffffffffff : 0;
    assign rvfi_csr_mcycle_rdata = retire_csrCycle_before;
    assign rvfi_csr_mcycle_wdata = retire_csrCycle_after;
    assign rvfi_csr_mcycle_wmask = retire_csrCycle_writeMask;
`endif
`ifdef RISCV_FORMAL_CSR_MINSTRET
    assign rvfi_csr_minstret_rmask = retire_valid ? 64'hffffffffffffffff : 0;
    assign rvfi_csr_minstret_rdata = retire_csrInstret_before;
    assign rvfi_csr_minstret_wdata = retire_csrInstret_after;
    assign rvfi_csr_minstret_wmask = retire_csrInstret_writeMask;
`endif
`ifdef RISCV_FORMAL_CSR_MISA
    assign rvfi_csr_misa_rmask = retire_valid ? 32'hffffffff : 0;
    assign rvfi_csr_misa_rdata = retire_misa;
    assign rvfi_csr_misa_wmask = 0;
    assign rvfi_csr_misa_wdata = retire_misa;
`endif
`ifdef RISCV_FORMAL_CSR_MSCRATCH
    assign rvfi_csr_mscratch_rmask = retire_csr_valid && retire_csr_address == 12'h340 ? retire_csr_readMask : 0;
    assign rvfi_csr_mscratch_wmask = retire_csr_valid && retire_csr_address == 12'h340 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mscratch_rdata = retire_csr_valid && retire_csr_address == 12'h340 ? retire_csr_readData : 0;
    assign rvfi_csr_mscratch_wdata = retire_csr_valid && retire_csr_address == 12'h340 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MIE
    assign rvfi_csr_mie_rmask = retire_csr_valid && retire_csr_address == 12'h304 ? retire_csr_readMask : 0;
    assign rvfi_csr_mie_wmask = retire_csr_valid && retire_csr_address == 12'h304 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mie_rdata = retire_csr_valid && retire_csr_address == 12'h304 ? retire_csr_readData : 0;
    assign rvfi_csr_mie_wdata = retire_csr_valid && retire_csr_address == 12'h304 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MTVEC
    assign rvfi_csr_mtvec_rmask = retire_csr_valid && retire_csr_address == 12'h305 ? retire_csr_readMask : 0;
    assign rvfi_csr_mtvec_wmask = retire_csr_valid && retire_csr_address == 12'h305 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mtvec_rdata = retire_csr_valid && retire_csr_address == 12'h305 ? retire_csr_readData : 0;
    assign rvfi_csr_mtvec_wdata = retire_csr_valid && retire_csr_address == 12'h305 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MIP
    assign rvfi_csr_mip_rmask = retire_csr_valid && retire_csr_address == 12'h344 ? retire_csr_readMask : 0;
    assign rvfi_csr_mip_wmask = retire_csr_valid && retire_csr_address == 12'h344 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mip_rdata = retire_csr_valid && retire_csr_address == 12'h344 ? retire_csr_readData : 0;
    assign rvfi_csr_mip_wdata = retire_csr_valid && retire_csr_address == 12'h344 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MCOUNTEREN
    assign rvfi_csr_mcounteren_rmask = retire_csr_valid && retire_csr_address == 12'h306 ? retire_csr_readMask : 0;
    assign rvfi_csr_mcounteren_wmask = retire_csr_valid && retire_csr_address == 12'h306 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mcounteren_rdata = retire_csr_valid && retire_csr_address == 12'h306 ? retire_csr_readData : 0;
    assign rvfi_csr_mcounteren_wdata = retire_csr_valid && retire_csr_address == 12'h306 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MCOUNTINHIBIT
    assign rvfi_csr_mcountinhibit_rmask = retire_csr_valid && retire_csr_address == 12'h320 ? retire_csr_readMask : 0;
    assign rvfi_csr_mcountinhibit_wmask = retire_csr_valid && retire_csr_address == 12'h320 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mcountinhibit_rdata = retire_csr_valid && retire_csr_address == 12'h320 ? retire_csr_readData : 0;
    assign rvfi_csr_mcountinhibit_wdata = retire_csr_valid && retire_csr_address == 12'h320 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MENVCFG
    assign rvfi_csr_menvcfg_rmask = retire_csr_valid && retire_csr_address == 12'h30a ? retire_csr_readMask : 0;
    assign rvfi_csr_menvcfg_wmask = retire_csr_valid && retire_csr_address == 12'h30a ? retire_csr_writeMask : 0;
    assign rvfi_csr_menvcfg_rdata = retire_csr_valid && retire_csr_address == 12'h30a ? retire_csr_readData : 0;
    assign rvfi_csr_menvcfg_wdata = retire_csr_valid && retire_csr_address == 12'h30a ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MENVCFGH
    assign rvfi_csr_menvcfgh_rmask = retire_csr_valid && retire_csr_address == 12'h31a ? retire_csr_readMask : 0;
    assign rvfi_csr_menvcfgh_wmask = retire_csr_valid && retire_csr_address == 12'h31a ? retire_csr_writeMask : 0;
    assign rvfi_csr_menvcfgh_rdata = retire_csr_valid && retire_csr_address == 12'h31a ? retire_csr_readData : 0;
    assign rvfi_csr_menvcfgh_wdata = retire_csr_valid && retire_csr_address == 12'h31a ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MVENDORID
    assign rvfi_csr_mvendorid_rmask = retire_csr_valid && retire_csr_address == 12'hf11 ? retire_csr_readMask : 0;
    assign rvfi_csr_mvendorid_wmask = retire_csr_valid && retire_csr_address == 12'hf11 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mvendorid_rdata = retire_csr_valid && retire_csr_address == 12'hf11 ? retire_csr_readData : 0;
    assign rvfi_csr_mvendorid_wdata = retire_csr_valid && retire_csr_address == 12'hf11 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MARCHID
    assign rvfi_csr_marchid_rmask = retire_csr_valid && retire_csr_address == 12'hf12 ? retire_csr_readMask : 0;
    assign rvfi_csr_marchid_wmask = retire_csr_valid && retire_csr_address == 12'hf12 ? retire_csr_writeMask : 0;
    assign rvfi_csr_marchid_rdata = retire_csr_valid && retire_csr_address == 12'hf12 ? retire_csr_readData : 0;
    assign rvfi_csr_marchid_wdata = retire_csr_valid && retire_csr_address == 12'hf12 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MIMPID
    assign rvfi_csr_mimpid_rmask = retire_csr_valid && retire_csr_address == 12'hf13 ? retire_csr_readMask : 0;
    assign rvfi_csr_mimpid_wmask = retire_csr_valid && retire_csr_address == 12'hf13 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mimpid_rdata = retire_csr_valid && retire_csr_address == 12'hf13 ? retire_csr_readData : 0;
    assign rvfi_csr_mimpid_wdata = retire_csr_valid && retire_csr_address == 12'hf13 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MHARTID
    assign rvfi_csr_mhartid_rmask = retire_csr_valid && retire_csr_address == 12'hf14 ? retire_csr_readMask : 0;
    assign rvfi_csr_mhartid_wmask = retire_csr_valid && retire_csr_address == 12'hf14 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mhartid_rdata = retire_csr_valid && retire_csr_address == 12'hf14 ? retire_csr_readData : 0;
    assign rvfi_csr_mhartid_wdata = retire_csr_valid && retire_csr_address == 12'hf14 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MCONFIGPTR
    assign rvfi_csr_mconfigptr_rmask = retire_csr_valid && retire_csr_address == 12'hf15 ? retire_csr_readMask : 0;
    assign rvfi_csr_mconfigptr_wmask = retire_csr_valid && retire_csr_address == 12'hf15 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mconfigptr_rdata = retire_csr_valid && retire_csr_address == 12'hf15 ? retire_csr_readData : 0;
    assign rvfi_csr_mconfigptr_wdata = retire_csr_valid && retire_csr_address == 12'hf15 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_MSTATUSH
    assign rvfi_csr_mstatush_rmask = retire_csr_valid && retire_csr_address == 12'h310 ? retire_csr_readMask : 0;
    assign rvfi_csr_mstatush_wmask = retire_csr_valid && retire_csr_address == 12'h310 ? retire_csr_writeMask : 0;
    assign rvfi_csr_mstatush_rdata = retire_csr_valid && retire_csr_address == 12'h310 ? retire_csr_readData : 0;
    assign rvfi_csr_mstatush_wdata = retire_csr_valid && retire_csr_address == 12'h310 ? retire_csr_writeData : 0;
`endif
`ifdef RISCV_FORMAL_CSR_TIME
    assign rvfi_csr_time_rmask = retire_valid ? 64'hffffffffffffffff : 0;
    assign rvfi_csr_time_rdata = retire_csrTime;
    assign rvfi_csr_time_wmask = 0;
    assign rvfi_csr_time_wdata = retire_csrTime;
`endif

`ifdef DITDAH_E2_RVFI_CONTRACT
    reg [63:0] expected_order = 0;
    reg handler_pending = 0;
    always @(posedge clock) begin
        if (reset) begin
            expected_order <= 0;
            handler_pending <= 0;
        end else begin
            if (rvfi_valid) begin
                assert(rvfi_order == expected_order);
                expected_order <= expected_order + 1;
                assert(rvfi_intr == handler_pending);
                assert(retire_length == 2 || retire_length == 4);
                if (retire_length == 2) assert(rvfi_insn[31:16] == 0);
                if (rvfi_rs1_addr == 0) assert(rvfi_rs1_rdata == 0);
                if (rvfi_rs2_addr == 0) assert(rvfi_rs2_rdata == 0);
                if (rvfi_rd_addr == 0) assert(rvfi_rd_wdata == 0);
                assert(rvfi_mem_addr[1:0] == 0);
                if (rvfi_trap) begin
                    assert(rvfi_rd_addr == 0 && rvfi_rd_wdata == 0);
                    assert(rvfi_mem_rmask == 0 && rvfi_mem_wmask == 0);
                    assert(retire_csrMcause_after == retire_cause);
                    assert(retire_csrMepc_after == (retire_pc &
                           (retire_misa[2] ? 32'hfffffffe : 32'hfffffffc)));
                    assert(!retire_csrMstatus_after[3]);
                    assert(retire_csrMstatus_after[7] == retire_csrMstatus_before[3]);
                end
                assert(((retire_csrMstatus_before ^ retire_csrMstatus_after) & ~retire_csrMstatus_writeMask) == 0);
                assert(((retire_csrMepc_before ^ retire_csrMepc_after) & ~retire_csrMepc_writeMask) == 0);
                assert(((retire_csrMcause_before ^ retire_csrMcause_after) & ~retire_csrMcause_writeMask) == 0);
                assert(((retire_csrMtval_before ^ retire_csrMtval_after) & ~retire_csrMtval_writeMask) == 0);
                handler_pending <= 0;
            end
            if ((rvfi_valid && rvfi_trap) || interrupt_valid) handler_pending <= 1;
        end
    end
`endif
endmodule
