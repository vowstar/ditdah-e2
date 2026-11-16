// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module axi_formal #(parameter CONCURRENT = 1)(input clock);
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

  reg [1:0] outstanding = 0, write = 0, machine = 0, rejected = 0, bus_done = 0;
  reg [1:0] ar_seen = 0;
  reg [31:0] address [0:1], data [0:1], result [0:1];
  reg [3:0] mask [0:1];
  reg [1:0] fault = 0;
  reg aw_seen = 0, w_seen = 0;
  reg [1:0] read_count = 0;
  reg read_head = 0, read_tail = 0, read_owner0 = 0, read_owner1 = 0;
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
  wire issuing_read = !axi_ar_bits_protection[2];
  wire returning_read = read_head ? read_owner1 : read_owner0;
  wire ir_bus = rr && !returning_read;
  wire dr_bus = rr && returning_read;
  reg aw_first = 0, w_first = 0, together = 0;
  reg [1:0] held = 0, saw = 0;

  always @(posedge clock) begin
    past_valid <= 1;
    if (reset) begin
      assume (!instruction_request_valid && !data_request_valid && !axi_b_valid && !axi_r_valid);
      outstanding <= 0;
      ar_seen <= 0;
      aw_seen <= 0;
      w_seen <= 0;
      bus_done <= 0;
      read_count <= 0;
      read_head <= 0;
      read_tail <= 0;
    end else begin
      assume (!instruction_request_bits_write);
      assume (!axi_b_valid || (outstanding[1] && write[1] && aw_seen && w_seen && !bus_done[1]));
      assume (!axi_r_valid || (read_count != 0 && outstanding[returning_read] &&
                              ar_seen[returning_read] && !bus_done[returning_read]));
      assume (!axi_b_valid || axi_b_bits_response != 2'b01);
      assume (!axi_r_valid || axi_r_bits_response != 2'b01);
      if (past_valid && !$past(reset)) begin
        if ($past(instruction_request_valid && !instruction_request_ready)) begin
          assume (instruction_request_valid);
          assume ($stable({instruction_request_bits_address, instruction_request_bits_write,
                           instruction_request_bits_data, instruction_request_bits_mask, instruction_request_bits_size,
                           instruction_request_bits_machine, instruction_request_bits_operation}));
        end
        if ($past(data_request_valid && !data_request_ready)) begin
          assume (data_request_valid);
          assume ($stable({data_request_bits_address, data_request_bits_write,
                           data_request_bits_data, data_request_bits_mask, data_request_bits_size,
                           data_request_bits_machine, data_request_bits_operation}));
        end
        if ($past(axi_b_valid && !axi_b_ready)) assume (axi_b_valid && $stable(axi_b_bits_response));
        if ($past(axi_r_valid && !axi_r_ready)) assume (axi_r_valid && $stable({axi_r_bits_response, axi_r_bits_data}));
        if ($past(axi_aw_valid && !axi_aw_ready))
          assert (axi_aw_valid && $stable({axi_aw_bits_address, axi_aw_bits_protection}));
        if ($past(axi_w_valid && !axi_w_ready))
          assert (axi_w_valid && $stable({axi_w_bits_data, axi_w_bits_strobe}));
        if ($past(axi_ar_valid && !axi_ar_ready))
          assert (axi_ar_valid && $stable({axi_ar_bits_address, axi_ar_bits_protection}));
        if ($past(instruction_response_valid && !instruction_response_ready))
          assert (instruction_response_valid && $stable({instruction_response_bits_data, instruction_response_bits_fault}));
        if ($past(data_response_valid && !data_response_ready))
          assert (data_response_valid && $stable({data_response_bits_data, data_response_bits_fault}));
      end
      assert (read_count <= (CONCURRENT ? 2 : 1));
      if (!CONCURRENT) begin
        assert (outstanding != 2'b11);
        assert (!(instruction_response_valid && data_response_valid));
        assert (!(iq && dq));
      end
      if (outstanding[0] && !ir) assert (!instruction_request_ready);
      if (outstanding[1] && !dr) assert (!data_request_ready);
      if (axi_aw_valid) begin
        assert (outstanding[1] && write[1] && !rejected[1] && !aw_seen && !bus_done[1]);
        assert (axi_aw_bits_address == {address[1][31:2], 2'b00});
        assert (axi_aw_bits_protection == {2'b00, machine[1]});
      end
      if (axi_w_valid) begin
        assert (outstanding[1] && write[1] && !rejected[1] && !w_seen && !bus_done[1]);
        assert (axi_w_bits_data == data[1] && axi_w_bits_strobe == mask[1]);
      end
      if (axi_ar_valid) begin
        assert (outstanding[issuing_read] && !write[issuing_read] && !rejected[issuing_read] &&
                !ar_seen[issuing_read] && !bus_done[issuing_read]);
        assert (axi_ar_bits_address == {address[issuing_read][31:2], 2'b00});
        assert (axi_ar_bits_protection == {!issuing_read, 1'b0, machine[issuing_read]});
      end
      if (axi_b_ready) assert (outstanding[1] && write[1] && aw_seen && w_seen && !bus_done[1]);
      if (axi_r_ready) assert (read_count != 0 && outstanding[returning_read] &&
                              ar_seen[returning_read] && !bus_done[returning_read]);
      if (aw) begin
        aw_seen <= 1;
        if (!w_seen && !wd) aw_first <= 1;
      end
      if (wd) begin
        w_seen <= 1;
        if (!aw_seen && !aw) w_first <= 1;
      end
      if (aw && wd) together <= 1;
      if (ar) begin
        ar_seen[issuing_read] <= 1;
        if (read_tail) read_owner1 <= issuing_read;
        else read_owner0 <= issuing_read;
        read_tail <= !read_tail;
      end
      if (rr) begin
        read_head <= !read_head;
        bus_done[returning_read] <= 1;
        result[returning_read] <= axi_r_bits_data;
        fault[returning_read] <= axi_r_bits_response != 0;
      end
      if (ar && !rr) read_count <= read_count + 1;
      if (rr && !ar) read_count <= read_count - 1;
      if (br) begin
        bus_done[1] <= 1;
        result[1] <= 0;
        fault[1] <= axi_b_bits_response != 0;
      end
      if (instruction_response_valid) begin
        assert (outstanding[0] && (bus_done[0] || ir_bus));
        assert (instruction_response_bits_data == (bus_done[0] ? result[0] : axi_r_bits_data));
        assert (instruction_response_bits_fault == (bus_done[0] ? fault[0] : axi_r_bits_response != 0));
        if (!ir) held[0] <= 1;
      end
      if (data_response_valid) begin
        assert (outstanding[1] && (bus_done[1] || dr_bus || br));
        assert (data_response_bits_data == (bus_done[1] ? result[1] : br ? 32'd0 : axi_r_bits_data));
        assert (data_response_bits_fault == (bus_done[1] ? fault[1] : br ? axi_b_bits_response != 0 : axi_r_bits_response != 0));
        if (!dr) held[1] <= 1;
      end
      if (outstanding[0] && rejected[0]) assert (instruction_response_valid);
      if (outstanding[1] && rejected[1]) assert (data_response_valid);
      if (ir) begin outstanding[0] <= 0; saw[0] <= 1; end
      if (dr) begin outstanding[1] <= 0; saw[1] <= 1; end
      if (iq) begin
        assert (!outstanding[0] || ir);
        outstanding[0] <= 1;
        write[0] <= instruction_request_bits_write;
        machine[0] <= instruction_request_bits_machine;
        address[0] <= instruction_request_bits_address;
        data[0] <= instruction_request_bits_data;
        mask[0] <= instruction_request_bits_mask;
        ar_seen[0] <= 0;
        bus_done[0] <= instruction_request_bits_operation != 0;
        rejected[0] <= instruction_request_bits_operation != 0;
        result[0] <= 0;
        fault[0] <= 1;
        held[0] <= 0;
      end
      if (dq) begin
        assert (!outstanding[1] || dr);
        outstanding[1] <= 1;
        write[1] <= data_request_bits_write;
        machine[1] <= data_request_bits_machine;
        address[1] <= data_request_bits_address;
        data[1] <= data_request_bits_data;
        mask[1] <= data_request_bits_mask;
        aw_seen <= 0;
        w_seen <= 0;
        ar_seen[1] <= 0;
        bus_done[1] <= data_request_bits_operation != 0;
        rejected[1] <= data_request_bits_operation != 0;
        result[1] <= 0;
        fault[1] <= 1;
        held[1] <= 0;
        aw_first <= 0;
        w_first <= 0;
        together <= 0;
      end
      cover (ir && machine[0]);
      cover (ir && !machine[0]);
      cover (dr && machine[1]);
      cover (dr && !machine[1]);
      cover (ir && rejected[0]);
      cover (dr && rejected[1]);
      cover (dr && aw_first);
      cover (dr && w_first);
      cover (dr && together);
      cover (ir && held[0]);
      cover (dr && held[1]);
      cover (ir && fault[0]);
      cover (dr && fault[1]);
      cover (saw[0] && saw[1] && (CONCURRENT ? iq && dq : iq || dq));
      cover (ir && ir_bus);
      cover (dr && br);
      cover (dr && dr_bus);
      cover (ir && iq);
      cover (ir && dq && !iq);
      cover ((ir && held[0] && iq) || (dr && held[1] && dq));
      cover (CONCURRENT ? iq && dq : iq && data_request_valid);
      cover (CONCURRENT ? read_count == 2 : dq && instruction_request_valid);
      cover (CONCURRENT ? read_count != 0 && write[1] && aw_seen && w_seen && !bus_done[1] :
             instruction_response_valid && !instruction_response_ready && data_request_valid && !data_request_ready);
      cover (CONCURRENT ? ir && dr : dr && iq);
    end
  end
endmodule
