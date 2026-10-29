// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module debug_latency_formal #(parameter TARGET = 0, PREFIX = 16, PROPERTY = 0, STEP = 0, ENABLE_M = 0, ENABLE_C = 0,
  ACCEPT_BOUND = 8, RESPONSE_BOUND = 24, DMI_BOUND = 8)(input clock);
  localparam HALT_BOUND = 2 * (ACCEPT_BOUND + RESPONSE_BOUND) + 8;
  localparam RESUME_BOUND = ACCEPT_BOUND + RESPONSE_BOUND + 6;
  localparam POLL_BOUND = 2 * (DMI_BOUND + 2);
  localparam STEP_BOUND = (ENABLE_C ? 4 : 3) * (ACCEPT_BOUND + RESPONSE_BOUND) + (ENABLE_M ? 34 : 0) + 16;
  localparam END_BOUND = PREFIX + HALT_BOUND + 2 * POLL_BOUND + 16 +
    (STEP ? STEP_BOUND + 3 * (DMI_BOUND + 2) : RESUME_BOUND);
  `define CHECK(expression) if (PROPERTY == 0) assert(expression)
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyconst *) reg [7:0] request_cycle;
  (* anyseq *) reg i_accept, d_accept, i_return, d_return, dmi_ready;
  (* anyseq *) reg [31:0] i_value, d_value;
  (* anyseq *) reg i_fault, d_fault;
  (* anyseq *) reg interrupts_software, interrupts_timer, interrupts_external;
  (* anyseq *) reg [63:0] timeValue;
  wire instruction_request_valid, instruction_request_ready;
  wire [31:0] instruction_request_bits_address, instruction_request_bits_data;
  wire instruction_request_bits_write, instruction_request_bits_machine;
  wire [3:0] instruction_request_bits_mask, instruction_request_bits_operation;
  wire [1:0] instruction_request_bits_size;
  wire instruction_response_valid, instruction_response_ready, instruction_response_bits_fault;
  wire [31:0] instruction_response_bits_data;
  wire data_request_valid, data_request_ready, data_request_bits_write, data_request_bits_machine;
  wire [31:0] data_request_bits_address, data_request_bits_data;
  wire [3:0] data_request_bits_mask, data_request_bits_operation;
  wire [1:0] data_request_bits_size;
  wire data_response_valid, data_response_ready, data_response_bits_fault;
  wire [31:0] data_response_bits_data;
  wire retire_valid, retire_writes, retire_trap, retire_userMode;
  wire [31:0] retire_pc, retire_word, retire_nextPc, retire_value, retire_cause, retire_tval;
  wire [4:0] retire_rd;
  wire loadUse, forward, redirect, memoryWait, sleeping, interrupt_valid;
  wire [31:0] interrupt_pc, interrupt_target, interrupt_cause;
  wire mulDiv_start, mulDiv_resultValid, mulDiv_finish, mulDiv_cancel;
  wire [31:0] mulDiv_pc, mulDiv_value;
  wire dmi_request_ready, dmi_response_valid, systemReset;
  wire dmi_response_ready = dmi_ready;
  reg dmi_request_valid;
  reg [6:0] dmi_request_bits_address;
  reg [31:0] dmi_request_bits_data;
  reg [1:0] dmi_request_bits_op;
  wire [31:0] dmi_response_bits_data;
  wire [1:0] dmi_response_bits_status;
  wire observed_halted, observed_resume, observed_ack, observed_stop, observed_m_valid, observed_step;
  DitDahE2 dut (
    .retire_order(), .retire_length(), .retire_insn(),
    .retire_intr(), .retire_rs1(), .retire_rs1Data(),
    .retire_rs2(), .retire_rs2Data(), .retire_memoryReadMask(),
    .retire_memoryReadData(), .retire_memoryOperation(), .retire_memoryResponse(),
    .retire_memoryFault(), .retire_faultReadMask(), .retire_misa(),
    .retire_csr_valid(), .retire_csr_address(), .retire_csr_readMask(),
    .retire_csrCycle_before(), .interrupt_csrMstatus_before(),
    .retire_memoryAddress(), .retire_memoryWriteMask(), .retire_memoryWriteData(),
    .retire_memoryOperand(), .retire_faultWriteMask(), .retire_csr_writeMask(),
    .retire_csr_readData(), .retire_csr_writeData(), .retire_csrMstatus_before(),
    .retire_csrMstatus_after(), .retire_csrMstatus_writeMask(), .retire_csrMepc_before(),
    .retire_csrMepc_after(), .retire_csrMepc_writeMask(), .retire_csrMcause_before(),
    .retire_csrMcause_after(), .retire_csrMcause_writeMask(), .retire_csrMtval_before(),
    .retire_csrMtval_after(), .retire_csrMtval_writeMask(), .retire_csrCycle_after(),
    .retire_csrCycle_writeMask(), .retire_csrInstret_before(), .retire_csrInstret_after(),
    .retire_csrInstret_writeMask(), .retire_csrTime(), .interrupt_userMode(),
    .interrupt_csrMstatus_after(), .interrupt_csrMstatus_writeMask(), .interrupt_csrMepc_before(),
    .interrupt_csrMepc_after(), .interrupt_csrMepc_writeMask(), .interrupt_csrMcause_before(),
    .interrupt_csrMcause_after(), .interrupt_csrMcause_writeMask(), .interrupt_csrMtval_before(),
    .interrupt_csrMtval_after(), .interrupt_csrMtval_writeMask(),
    .*
  );

  reg i_busy = 0, d_busy = 0, i_offered = 0, d_offered = 0;
  reg i_available = 0, d_available = 0;
  reg [31:0] i_payload, d_payload;
  reg i_error, d_error;
  reg [7:0] i_offer_age = 0, d_offer_age = 0, i_age = 0, d_age = 0, dmi_age = 0;
  assign instruction_request_ready = !i_busy && i_accept;
  assign data_request_ready = !d_busy && d_accept;
  assign instruction_response_valid = i_busy && (i_available || i_return);
  assign data_response_valid = d_busy && (d_available || d_return);
  assign instruction_response_bits_data = i_payload;
  assign data_response_bits_data = d_payload;
  assign instruction_response_bits_fault = i_error;
  assign data_response_bits_fault = d_error;
  wire iq = instruction_request_valid && instruction_request_ready;
  wire dq = data_request_valid && data_request_ready;
  wire is = instruction_response_valid && instruction_response_ready;
  wire ds = data_response_valid && data_response_ready;
  wire cq = dmi_request_valid && dmi_request_ready;
  wire cs = dmi_response_valid && dmi_response_ready;

  reg [3:0] phase = 0;
  reg dmi_owned = 0;
  reg snapshot_halted = 0;
  reg [9:0] cycle = 0, halt_start = 0, resume_start = 0;
  reg [9:0] halt_status_cycle = 0, resume_status_cycle = 0, step_status_cycle = 0;
  reg halt_requested = 0, halt_seen = 0, halt_polled = 0;
  reg resume_requested = 0, resume_seen = 0, resume_polled = 0;
  reg halt_with_i_accepted = 0, halt_with_d_accepted = 0;
  reg halt_with_i_offered = 0, halt_with_d_offered = 0;
  reg halt_with_m = 0;
  reg step_started = 0, step_halted = 0, step_polled = 0;
  reg [1:0] step_count = 0;
  reg step_retired = 0, step_trapped = 0, step_memory = 0, step_multiply = 0, step_crossing = 0;
  wire halt_expired = halt_requested && !halt_seen && !observed_halted && cycle - halt_start >= HALT_BOUND;
  wire resume_expired = resume_requested && !resume_seen && !observed_ack && cycle - resume_start >= RESUME_BOUND;
  wire halt_poll_expired = halt_seen && !halt_polled && cycle - halt_status_cycle >= POLL_BOUND;
  wire resume_poll_expired = resume_seen && !resume_polled && cycle - resume_status_cycle >= POLL_BOUND;
  wire step_expired = STEP && resume_requested && !step_halted && cycle - resume_start >= STEP_BOUND;
  wire step_poll_expired = step_halted && !step_polled && cycle - step_status_cycle >= POLL_BOUND;
  wire extra_step = step_started && retire_valid && step_count != 0;
  wire finished = phase == 5;
  always @* begin
    dmi_request_valid = !reset && !dmi_owned && phase != 5 && (phase != 1 || cycle >= request_cycle);
    dmi_request_bits_address = 7'h10;
    dmi_request_bits_data = 1;
    dmi_request_bits_op = 2;
    case (phase)
      1: dmi_request_bits_data = 32'h80000001;
      2, 4: begin dmi_request_bits_address = 7'h11; dmi_request_bits_op = 1; end
      3: dmi_request_bits_data = 32'h40000001;
      6: begin dmi_request_bits_address = 4; dmi_request_bits_data = 7; end
      7: begin dmi_request_bits_address = 7'h17; dmi_request_bits_data = 32'h002307b0; end
      8: begin dmi_request_bits_address = 7'h16; dmi_request_bits_op = 1; end
      default: begin end
    endcase
  end

  always @(posedge clock) begin
    assume(request_cycle >= 2 && request_cycle <= PREFIX);
    if (!reset) begin
      if (cycle != 1023) cycle <= cycle + 1;
      if (PROPERTY == 0 && instruction_request_valid && !i_busy && i_offer_age == ACCEPT_BOUND - 1) assume(i_accept);
      if (PROPERTY == 0 && data_request_valid && !d_busy && d_offer_age == ACCEPT_BOUND - 1) assume(d_accept);
      if (PROPERTY == 0 && i_busy && i_age == RESPONSE_BOUND - 1) assume(i_return);
      if (PROPERTY == 0 && d_busy && d_age == RESPONSE_BOUND - 1) assume(d_return);
      if (PROPERTY == 0 && dmi_response_valid && dmi_age == DMI_BOUND - 1) assume(dmi_ready);
      i_offer_age <= instruction_request_valid && !instruction_request_ready ? i_offer_age + 1 : 0;
      d_offer_age <= data_request_valid && !data_request_ready ? d_offer_age + 1 : 0;
      i_offered <= instruction_request_valid && !instruction_request_ready;
      d_offered <= data_request_valid && !data_request_ready;
      if (i_busy) i_age <= i_age + 1;
      if (d_busy) d_age <= d_age + 1;
      dmi_age <= dmi_response_valid && !dmi_response_ready ? dmi_age + 1 : 0;
      if (iq) begin
        `CHECK(!i_busy);
        i_busy <= 1;
        i_age <= 0;
        i_available <= 0;
        i_payload <= i_value;
        i_error <= i_fault;
      end
      if (dq) begin
        `CHECK(!d_busy);
        d_busy <= 1;
        d_age <= 0;
        d_available <= 0;
        d_payload <= d_value;
        d_error <= d_fault;
      end
      if (instruction_response_valid) i_available <= 1;
      if (data_response_valid) d_available <= 1;
      if (is) begin i_busy <= 0; i_available <= 0; end
      if (ds) begin d_busy <= 0; d_available <= 0; end
      if (i_offered) begin
        assert(instruction_request_valid);
        if (PROPERTY == 1) assert($stable({instruction_request_bits_address, instruction_request_bits_data,
          instruction_request_bits_write, instruction_request_bits_machine,
          instruction_request_bits_mask, instruction_request_bits_size, instruction_request_bits_operation}));
      end
      if (d_offered) begin
        assert(data_request_valid);
        if (PROPERTY == 1) assert($stable({data_request_bits_address, data_request_bits_data,
          data_request_bits_write, data_request_bits_machine,
          data_request_bits_mask, data_request_bits_size, data_request_bits_operation}));
      end
      `CHECK(!observed_halted || (!i_busy && !d_busy && !instruction_request_valid && !data_request_valid && !observed_m_valid));
      `CHECK(!systemReset);
      `CHECK(!halt_expired && !resume_expired && !halt_poll_expired && !resume_poll_expired);
      `CHECK(!step_expired && !step_poll_expired && !extra_step);
      if (cycle >= PREFIX + DMI_BOUND + 4) `CHECK(halt_requested);
      if (cycle >= END_BOUND) `CHECK(finished);
      if (halt_requested && !resume_requested) `CHECK(observed_stop);
      if (halt_requested && observed_halted && !halt_seen) begin halt_seen <= 1; halt_status_cycle <= cycle; end
      if (resume_requested && observed_ack && !resume_seen) begin resume_seen <= 1; resume_status_cycle <= cycle; end
      if (STEP && resume_requested && observed_resume) begin
        `CHECK(!step_started);
        step_started <= 1;
      end
      if (step_started) begin
        `CHECK(!interrupt_valid);
        if (!observed_halted) `CHECK(observed_step);
        if (retire_valid) begin
          step_count <= step_count + 1;
          if (retire_trap) step_trapped <= 1;
          else step_retired <= 1;
          if (retire_pc[1] && retire_word[1:0] == 3 && !retire_trap) step_crossing <= 1;
        end
        if (dq) step_memory <= 1;
        if (mulDiv_start) step_multiply <= 1;
        if (observed_halted) begin
          `CHECK(step_count == 1 && (step_retired != step_trapped));
          if (!step_halted) begin step_halted <= 1; step_status_cycle <= cycle; end
        end
      end
      if (cq) begin
        `CHECK(!dmi_owned);
        dmi_owned <= 1;
        snapshot_halted <= observed_halted;
        if (phase == 1) begin
          halt_requested <= 1;
          halt_start <= cycle;
          halt_with_i_accepted <= i_busy || iq;
          halt_with_d_accepted <= d_busy || dq;
          halt_with_i_offered <= instruction_request_valid && !instruction_request_ready;
          halt_with_d_offered <= data_request_valid && !data_request_ready;
          halt_with_m <= observed_m_valid;
        end
        if (phase == 3) begin
          `CHECK(halt_seen && halt_polled && observed_halted);
          resume_requested <= 1;
          resume_start <= cycle;
        end
      end
      if (cs) begin
        `CHECK(dmi_owned && dmi_response_bits_status == 0);
        dmi_owned <= 0;
        case (phase)
          0: phase <= 1;
          1: phase <= 2;
          2: begin
            `CHECK((dmi_response_bits_data[9:8] == 3) == snapshot_halted);
            if (dmi_response_bits_data[9:8] == 3) begin halt_polled <= 1; phase <= STEP ? 6 : 3; end
          end
          3: phase <= 4;
          4: if (dmi_response_bits_data[17:16] == 3) begin
            `CHECK(resume_seen);
            resume_polled <= 1;
            if (!STEP) begin `CHECK(!snapshot_halted); phase <= 5; end
            else if (dmi_response_bits_data[9:8] == 3) begin
              `CHECK(step_halted && snapshot_halted);
              step_polled <= 1;
              phase <= 5;
            end
          end
          6: phase <= 7;
          7: phase <= 8;
          8: begin
            `CHECK(dmi_response_bits_data[10:8] == 0);
            if (!dmi_response_bits_data[12]) phase <= 3;
          end
          default: `CHECK(0);
        endcase
      end
`ifdef REACHABILITY
      if (TARGET == 0) `CHECK(!finished);
      if (TARGET == 1) `CHECK(!(finished && halt_with_i_accepted));
      if (TARGET == 2) `CHECK(!(finished && halt_with_d_accepted));
      if (TARGET == 3) `CHECK(!(finished && halt_with_i_offered));
      if (TARGET == 4) `CHECK(!(finished && halt_with_d_offered));
      if (TARGET == 5) `CHECK(!(finished && step_retired));
      if (TARGET == 6) `CHECK(!(finished && step_trapped));
      if (TARGET == 7) `CHECK(!(finished && step_memory));
      if (TARGET == 8) `CHECK(!(finished && step_multiply && step_retired && retire_word[6:0] == 7'h33 && retire_word[31:25] == 1));
      if (TARGET == 9) `CHECK(!(finished && step_crossing));
`endif
    end
  end
  `undef CHECK
endmodule
