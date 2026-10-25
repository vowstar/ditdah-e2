// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module axi_formal(input clock);
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyseq *) reg instruction_request_valid, data_request_valid;
  (* anyseq *) reg [31:0] instruction_request_bits_address, instruction_request_bits_data;
  (* anyseq *) reg [31:0] data_request_bits_address, data_request_bits_data;
  (* anyseq *) reg instruction_request_bits_machine, data_request_bits_machine;
  (* anyseq *) reg instruction_request_bits_write, data_request_bits_write;
  (* anyseq *) reg [3:0] instruction_request_bits_mask, data_request_bits_mask;
  (* anyseq *) reg [3:0] instruction_request_bits_operation, data_request_bits_operation;
  (* anyseq *) reg [1:0] instruction_request_bits_size, data_request_bits_size;
  (* anyseq *) reg instruction_response_ready, data_response_ready;
  (* anyseq *) reg axi_aw_ready, axi_w_ready, axi_ar_ready, axi_b_valid, axi_r_valid;
  (* anyseq *) reg [1:0] axi_b_bits_response, axi_r_bits_response;
  (* anyseq *) reg [31:0] axi_r_bits_data;
  wire instruction_request_ready, data_request_ready;
  wire instruction_response_valid, instruction_response_bits_fault;
  wire data_response_valid, data_response_bits_fault;
  wire [31:0] instruction_response_bits_data, data_response_bits_data;
  wire axi_aw_valid, axi_w_valid, axi_ar_valid, axi_b_ready, axi_r_ready;
  wire [31:0] axi_aw_bits_address, axi_w_bits_data, axi_ar_bits_address;
  wire [2:0] axi_aw_bits_protection, axi_ar_bits_protection;
  wire [3:0] axi_w_bits_strobe;
  DitDahE2AxiLite dut(.*);

  reg outstanding = 0, owner = 0, write = 0, prefer_data = 0;
  reg [31:0] address, data, result;
  reg [3:0] mask;
  reg fault, machine, rejected;
  reg aw_seen = 0, w_seen = 0, ar_seen = 0, bus_done = 0;
  reg past_valid = 0;
  wire iq = instruction_request_valid && instruction_request_ready;
  wire dq = data_request_valid && data_request_ready;
  wire ir = instruction_response_valid && instruction_response_ready;
  wire dr = data_response_valid && data_response_ready;
  wire aw = axi_aw_valid && axi_aw_ready;
  wire wd = axi_w_valid && axi_w_ready;
  wire ar = axi_ar_valid && axi_ar_ready;
  wire br = axi_b_valid && axi_b_ready;
  wire rr = axi_r_valid && axi_r_ready;
  reg aw_first = 0, w_first = 0, together = 0, held = 0, saw_instruction = 0, saw_data = 0;

  always @(posedge clock) begin
    past_valid <= 1;
    if (reset) begin
      assume (!instruction_request_valid && !data_request_valid && !axi_b_valid && !axi_r_valid);
      outstanding <= 0;
      aw_seen <= 0;
      w_seen <= 0;
      ar_seen <= 0;
      bus_done <= 0;
      prefer_data <= 0;
    end else begin
      assume (!instruction_request_bits_write);
      assume (!axi_b_valid || (outstanding && write && aw_seen && w_seen && !bus_done));
      assume (!axi_r_valid || (outstanding && !write && ar_seen && !bus_done));
      assume (!axi_b_valid || axi_b_bits_response != 2'b01);
      assume (!axi_r_valid || axi_r_bits_response != 2'b01);
      if (past_valid && !$past(reset)) begin
        if ($past(instruction_request_valid && !instruction_request_ready)) begin
          assume (instruction_request_valid);
          assume ($stable({instruction_request_bits_address, instruction_request_bits_write,
                           instruction_request_bits_data, instruction_request_bits_mask, instruction_request_bits_size, instruction_request_bits_machine, instruction_request_bits_operation}));
        end
        if ($past(data_request_valid && !data_request_ready)) begin
          assume (data_request_valid);
          assume ($stable({data_request_bits_address, data_request_bits_write,
                           data_request_bits_data, data_request_bits_mask, data_request_bits_size, data_request_bits_machine, data_request_bits_operation}));
        end
        if ($past(axi_b_valid && !axi_b_ready)) begin
          assume (axi_b_valid && $stable(axi_b_bits_response));
        end
        if ($past(axi_r_valid && !axi_r_ready)) begin
          assume (axi_r_valid && $stable({axi_r_bits_response, axi_r_bits_data}));
        end
        if ($past(axi_aw_valid && !axi_aw_ready)) begin
          assert (axi_aw_valid && $stable({axi_aw_bits_address, axi_aw_bits_protection}));
        end
        if ($past(axi_w_valid && !axi_w_ready)) begin
          assert (axi_w_valid && $stable({axi_w_bits_data, axi_w_bits_strobe}));
        end
        if ($past(axi_ar_valid && !axi_ar_ready)) begin
          assert (axi_ar_valid && $stable({axi_ar_bits_address, axi_ar_bits_protection}));
        end
        if ($past(instruction_response_valid && !instruction_response_ready)) begin
          assert (instruction_response_valid && $stable({instruction_response_bits_data, instruction_response_bits_fault}));
        end
        if ($past(data_response_valid && !data_response_ready)) begin
          assert (data_response_valid && $stable({data_response_bits_data, data_response_bits_fault}));
        end
      end
      assert (!(iq && dq));
      assert (!(instruction_response_valid && data_response_valid));
      if (outstanding) assert (!instruction_request_ready && !data_request_ready);
      if (iq || dq) begin
        assert (!outstanding);
        if (instruction_request_valid && data_request_valid) assert (dq == prefer_data);
        outstanding <= 1;
        owner <= dq;
        machine <= dq ? data_request_bits_machine : instruction_request_bits_machine;
        prefer_data <= !dq;
        write <= dq ? data_request_bits_write : instruction_request_bits_write;
        address <= dq ? data_request_bits_address : instruction_request_bits_address;
        data <= dq ? data_request_bits_data : instruction_request_bits_data;
        mask <= dq ? data_request_bits_mask : instruction_request_bits_mask;
        aw_seen <= 0;
        w_seen <= 0;
        ar_seen <= 0;
        bus_done <= (dq ? data_request_bits_operation : instruction_request_bits_operation) != 0;
        rejected <= (dq ? data_request_bits_operation : instruction_request_bits_operation) != 0;
        result <= 0;
        fault <= 1;
        aw_first <= 0;
        w_first <= 0;
        together <= 0;
        held <= 0;
      end
      if (axi_aw_valid) begin
        assert (outstanding && write && !aw_seen && !bus_done);
        assert (axi_aw_bits_address == {address[31:2], 2'b00});
        assert (axi_aw_bits_protection == {!owner, 1'b0, machine});
      end
      if (axi_w_valid) begin
        assert (outstanding && write && !w_seen && !bus_done);
        assert (axi_w_bits_data == data && axi_w_bits_strobe == mask);
      end
      if (axi_ar_valid) begin
        assert (outstanding && !write && !ar_seen && !bus_done);
        assert (axi_ar_bits_address == {address[31:2], 2'b00});
        assert (axi_ar_bits_protection == {!owner, 1'b0, machine});
      end
      if (axi_b_ready) assert (outstanding && write && aw_seen && w_seen && !bus_done);
      if (axi_r_ready) assert (outstanding && !write && ar_seen && !bus_done);
      if (aw) begin
        aw_seen <= 1;
        if (!w_seen && !wd) aw_first <= 1;
      end
      if (wd) begin
        w_seen <= 1;
        if (!aw_seen && !aw) w_first <= 1;
      end
      if (aw && wd) together <= 1;
      if (ar) ar_seen <= 1;
      if (br || rr) begin
        assert (!bus_done);
        bus_done <= 1;
        result <= br ? 32'd0 : axi_r_bits_data;
        fault <= br ? axi_b_bits_response != 0 : axi_r_bits_response != 0;
      end
      if (instruction_response_valid || data_response_valid) begin
        assert (outstanding && bus_done);
        assert (data_response_valid == owner);
        assert ((owner ? data_response_bits_data : instruction_response_bits_data) == result);
        assert ((owner ? data_response_bits_fault : instruction_response_bits_fault) == fault);
        if (!(ir || dr)) held <= 1;
      end
      if (outstanding && rejected) begin
        assert (owner ? data_response_valid : instruction_response_valid);
        assert (!axi_aw_valid && !axi_w_valid && !axi_ar_valid && !axi_b_ready && !axi_r_ready);
      end
      if (ir || dr) begin
        outstanding <= 0;
        if (ir) saw_instruction <= 1;
        if (dr) saw_data <= 1;
      end
      cover (ir && machine);
      cover (ir && !machine);
      cover (dr && machine);
      cover (dr && !machine);
      cover (ir && rejected);
      cover (dr && rejected);
      cover (dr && aw_first);
      cover (dr && w_first);
      cover (dr && together);
      cover (ir && held);
      cover (dr && held);
      cover (ir && fault);
      cover (dr && fault);
      cover (saw_instruction && saw_data && instruction_request_valid && data_request_valid && iq);
    end
  end
endmodule
