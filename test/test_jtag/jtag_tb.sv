// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
`timescale 1ns/1ps
module jtag_tb;
  reg clock = 0, tck = 0, reset = 1, trstN = 0, tms = 1, tdi = 0;
  wire tdo, tdoEnable, requestReady, requestValid, responseReady;
  wire [6:0] requestAddress;
  wire [31:0] requestData;
  wire [1:0] requestOp;
  integer systemHalf = 5, seed = 17, cycles = 0, accepted = 0, completed = 0, writes = 0;
  reg [31:0] idcode;
  reg systemRun = 1, holdRequest = 0, holdResponse = 0, zeroLatency = 0;
  reg [1:0] forcedStatus = 0;
  reg active = 0;
  integer delayCount = 0;
  reg [31:0] memory [0:127], savedData;
  integer writeCount [0:127];
  reg [1:0] savedStatus;
  wire dmReady = !holdRequest && !active && cycles % 4 != 0;
  wire dmValid;
  wire [6:0] dmAddress;
  wire [31:0] dmData;
  wire [1:0] dmOp;
  wire dmResponseValid = !holdResponse && ((active && delayCount == 0) ||
                                            (zeroLatency && dmValid && dmReady));
  wire dmResponseReady;
  wire [31:0] dmResponseData = active ? savedData : memory[dmAddress];
  wire [1:0] dmResponseStatus = active ? savedStatus : forcedStatus;
  reg manual = 0, manualValid = 0, manualReady = 0;
  reg [6:0] manualAddress = 0;
  reg [31:0] manualData = 0;
  reg [1:0] manualOp = 0;
  wire bridgeValid;
  wire [31:0] bridgeData;
  wire [1:0] bridgeStatus;
  integer zeroResponses = 0, delayedResponses = 0;
  integer requestStallCycles = 0, responseStallCycles = 0;
  integer preservedRequests = 0, preservedResponses = 0;
  reg heldDmRequest = 0;
  reg [40:0] heldDmPayload;
  reg sawStickyBusy = 0, sawStickyFailed = 0;
  reg sawSystemStop = 0, sawTckStop = 0;

  DitDahE2JtagDtm dtm(
    .tck(tck), .reset(reset), .trstN(trstN), .tms(tms), .tdi(tdi),
    .tdo(tdo), .tdoEnable(tdoEnable),
    .dmi_request_ready(requestReady && !manual), .dmi_request_valid(requestValid),
    .dmi_request_bits_address(requestAddress), .dmi_request_bits_data(requestData),
    .dmi_request_bits_op(requestOp), .dmi_response_ready(responseReady),
    .dmi_response_valid(bridgeValid && !manual), .dmi_response_bits_data(bridgeData),
    .dmi_response_bits_status(bridgeStatus));
  DitDahE2DmiBridge bridge(
    .clock(clock), .tck(tck), .reset(reset),
    .upstream_request_ready(requestReady),
    .upstream_request_valid(manual ? manualValid : requestValid),
    .upstream_request_bits_address(manual ? manualAddress : requestAddress),
    .upstream_request_bits_data(manual ? manualData : requestData),
    .upstream_request_bits_op(manual ? manualOp : requestOp),
    .upstream_response_ready(manual ? manualReady : responseReady),
    .upstream_response_valid(bridgeValid), .upstream_response_bits_data(bridgeData),
    .upstream_response_bits_status(bridgeStatus),
    .downstream_request_ready(dmReady), .downstream_request_valid(dmValid),
    .downstream_request_bits_address(dmAddress), .downstream_request_bits_data(dmData),
    .downstream_request_bits_op(dmOp), .downstream_response_ready(dmResponseReady),
    .downstream_response_valid(dmResponseValid), .downstream_response_bits_data(dmResponseData),
    .downstream_response_bits_status(dmResponseStatus));

  initial forever begin #(systemHalf); clock = systemRun ? !clock : 0; end
  always @(posedge clock) begin
    if (reset) begin
      cycles <= 0; accepted <= 0; completed <= 0; writes <= 0; active <= 0;
      zeroResponses <= 0; delayedResponses <= 0; requestStallCycles <= 0;
      responseStallCycles <= 0; heldDmRequest <= 0;
      for (integer n = 0; n < 128; n++) begin
        memory[n] <= 32'h13579bdf ^ (n * 32'h10203);
        writeCount[n] <= 0;
      end
    end else begin
      cycles <= cycles + 1;
      if (heldDmRequest) begin
        check(dmValid, "Downstream request valid dropped under backpressure");
        check({dmAddress, dmData, dmOp} == heldDmPayload,
              "Downstream request payload changed under backpressure");
      end
      heldDmRequest <= dmValid && !dmReady;
      if (dmValid && !dmReady) begin
        heldDmPayload <= {dmAddress, dmData, dmOp};
        requestStallCycles <= requestStallCycles + 1;
      end
      if (manual && bridgeValid && !manualReady)
        responseStallCycles <= responseStallCycles + 1;
      if (active && delayCount != 0) delayCount <= delayCount - 1;
      if (dmValid && dmReady) begin
        accepted <= accepted + 1;
        if (dmOp == 2) begin
          memory[dmAddress] <= dmData;
          writeCount[dmAddress] <= writeCount[dmAddress] + 1;
          writes <= writes + 1;
        end
        if (!zeroLatency) begin
          active <= 1;
          delayCount <= 1 + cycles % 11;
          savedData <= memory[dmAddress];
          savedStatus <= forcedStatus;
        end
      end
      if (dmResponseValid && dmResponseReady) begin
        active <= 0;
        completed <= completed + 1;
        if (active) delayedResponses <= delayedResponses + 1;
        else if (zeroLatency && dmValid && dmReady) zeroResponses <= zeroResponses + 1;
        else check(0, "Downstream response lacks an accepted request");
      end
    end
  end

  task automatic check(input bit condition, input string message);
    if (!condition) $fatal(1, "%s", message);
  endtask

  task automatic cycle(input bit select, input bit data, output bit sampled);
    tms = select; tdi = data;
    seed = (seed * 1103515245 + 12345) & 32'h7fffffff;
    #(2 + seed % 4); sampled = tdo;
    tck = 1; #5; tck = 0; #3;
  endtask

  bit ignored;
  task automatic idle(input integer count);
    repeat (count) cycle(0, 0, ignored);
  endtask

  task automatic wait_response;
    integer count;
    count = 0;
    while (!bridgeValid) begin
      idle(1); count++;
      check(count < 2048, "Bridge completes under downstream progress");
    end
  endtask

  task automatic scan_ir(input reg [4:0] value);
    reg [4:0] captured;
    captured = 0;
    cycle(1, 0, ignored); cycle(1, 0, ignored); cycle(0, 0, ignored); cycle(0, 0, ignored);
    for (integer n = 0; n < 5; n++) begin
      check(tdoEnable, "TDO disabled during IR shift");
      cycle(n == 4, value[n], captured[n]);
    end
    cycle(1, 0, ignored); cycle(0, 0, ignored);
    check(captured[1:0] == 1, "IR capture low bits");
    check(!tdoEnable, "TDO enabled outside a shift state");
  endtask

  task automatic scan_dr(input reg [40:0] value, input integer width,
                         output reg [40:0] captured);
    captured = 0;
    cycle(1, 0, ignored); cycle(0, 0, ignored); cycle(0, 0, ignored);
    for (integer n = 0; n < width; n++) begin
      check(tdoEnable, "TDO disabled during DR shift");
      cycle(n == width - 1, value[n], captured[n]);
    end
    cycle(1, 0, ignored); cycle(0, 0, ignored);
    check(!tdoEnable, "TDO enabled outside a shift state");
  endtask

  reg [40:0] result;
  task automatic control(input reg [31:0] value);
    scan_ir(16); scan_dr({9'b0, value}, 32, result); scan_ir(17);
  endtask

  task automatic read_dtmcs(output reg [31:0] value);
    scan_ir(16); scan_dr(0, 32, result); value = result[31:0]; scan_ir(17);
  endtask

  task automatic request(input reg [1:0] op, input reg [6:0] address,
                         input reg [31:0] data);
    scan_ir(17); scan_dr({address, data, op}, 41, result);
  endtask

  task automatic poll(output reg [40:0] value);
    integer attempts;
    attempts = 0;
    do begin
      idle(16); scan_dr(0, 41, value);
      if (value[1:0] == 3) control(32'h10000);
      attempts++;
      check(attempts < 100, "DMI completes under downstream progress");
    end while (value[1:0] == 3);
  endtask

  task automatic access(input reg [1:0] op, input reg [6:0] address,
                        input reg [31:0] data);
    integer previousWrites;
    previousWrites = writeCount[address];
    request(op, address, data); poll(result);
    check(result[1:0] == 0, "DMI success");
    check(result[40:34] == address, "DMI response address");
    if (op == 2) begin
      check(memory[address] == data, "DMI write reaches its intended address and data");
      check(writeCount[address] == previousWrites + 1,
            "Non-idempotent DMI write accepted exactly once");
    end
    if (op == 1)
      check(result[33:2] == memory[address],
            $sformatf("DMI address %h: got %h, expected %h; accepted=%0d completed=%0d",
                      address, result[33:2], memory[address], accepted, completed));
  endtask

  task automatic apply_dtm_reset(input integer kind);
    case (kind)
      0: control(32'h20000);
      1: begin
        trstN = 0; #100;
        repeat (4) cycle(1, 0, ignored);
        trstN = 1;
        repeat (6) cycle(1, 0, ignored); idle(2);
      end
      default: begin repeat (6) cycle(1, 0, ignored); idle(2); end
    endcase
    if (kind != 0) begin
      scan_dr(0, 32, result);
      check(result == {9'b0, idcode}, "TAP reset restores IDCODE selection");
    end
  endtask

  task automatic manual_request(input reg [1:0] op, input reg [6:0] address,
                                input reg [31:0] data);
    integer attempts;
    manual = 1; manualReady = 0;
    manualOp = op; manualAddress = address; manualData = data; manualValid = 1;
    attempts = 0;
    while (!requestReady) begin
      cycle(0, 0, ignored); attempts++;
      check(attempts < 100, "Manual request eventually accepted");
    end
    cycle(0, 0, ignored); manualValid = 0;
  endtask

  task automatic manual_finish;
    manualReady = 1; cycle(0, 0, ignored); manualReady = 0;
    check(!bridgeValid, "Bridge response retires exactly once");
    manual = 0; idle(2);
  endtask

  task automatic preserve_response(input integer kind, input reg [6:0] address);
    reg [33:0] held;
    reg [31:0] dtmcs;
    manual_request(1, address, 0); wait_response();
    held = {bridgeData, bridgeStatus};
    check(bridgeValid && held == {memory[address], 2'b0}, "Expected manual read response");
    repeat (4) begin
      cycle(0, 0, ignored);
      check(bridgeValid && {bridgeData, bridgeStatus} == held,
            "Response payload stable under upstream backpressure");
    end
    apply_dtm_reset(kind);
    check(bridgeValid && {bridgeData, bridgeStatus} == held,
          "DTM reset preserves bridge response debt");
    read_dtmcs(dtmcs);
    check(dtmcs == 32'h1071, "DTM reset clears logical DTM state");
    repeat (4) begin
      cycle(0, 0, ignored);
      check(bridgeValid && {bridgeData, bridgeStatus} == held,
            "Preserved response remains stable");
    end
    preservedResponses++;
    manual_finish();
  endtask

  task automatic preserve_request(input integer kind, input reg [6:0] address);
    reg [6:0] rejected;
    reg [31:0] dtmcs;
    integer beforeAccepted, beforeWrites, beforeAddressWrites, beforeRejectedWrites;
    rejected = address + 1;
    beforeAccepted = accepted; beforeWrites = writes;
    beforeAddressWrites = writeCount[address];
    beforeRejectedWrites = writeCount[rejected];
    holdRequest = 1;
    request(2, address, 32'hace00000 | address); idle(16);
    check(accepted == beforeAccepted, "Downstream backpressure blocks acceptance");
    apply_dtm_reset(kind);
    read_dtmcs(dtmcs);
    check(dtmcs == 32'h1071, "DTM reset clears busy and failed status");
    request(2, rejected, 32'hbad00000 | rejected);
    scan_dr(0, 41, result);
    check(result[1:0] == 3, "Retained bridge owner backpressures a new request");
    check(accepted == beforeAccepted && writes == beforeWrites,
          "Reset and busy scans do not accept a replacement write");
    holdRequest = 0; idle(128); control(32'h10000);
    access(1, address, 0);
    check(accepted == beforeAccepted + 2 && writes == beforeWrites + 1,
          "Accepted request completes once after DTM reset");
    check(writeCount[address] == beforeAddressWrites + 1 &&
          writeCount[rejected] == beforeRejectedWrites,
          "DTM reset neither replays nor substitutes a non-idempotent write");
    preservedRequests++;
  endtask

  integer beforeCount, beforeWrites, beforeAddressWrites, beforeRejectedWrites;
  reg [31:0] dtmcs;
  reg [33:0] heldResponse;
  initial begin
    if ($value$plusargs("SYSTEM_HALF=%d", systemHalf)) begin end
    if ($value$plusargs("SEED=%d", seed)) begin end
    check($value$plusargs("IDCODE=%h", idcode), "Explicit test IDCODE");
    check(idcode != 0 && idcode[0], "Test IDCODE is nonzero and odd");
    repeat (8) cycle(1, 0, ignored);
    reset = 0;
    manual_request(2, 7'h30, 32'h76543210);
    wait_response();
    check(bridgeValid, "First request survives independent system reset release");
    heldResponse = {bridgeData, bridgeStatus};
    repeat (4) begin
      cycle(0, 0, ignored);
      check(bridgeValid && {bridgeData, bridgeStatus} == heldResponse,
            "Initial response stable under backpressure");
    end
    manual_finish(); trstN = 1;
    repeat (6) cycle(1, 0, ignored); idle(4);
    scan_dr(0, 32, result);
    check(result == {9'b0, idcode}, "Explicit test IDCODE after reset");
    read_dtmcs(dtmcs); check(dtmcs == 32'h1071, "DTMCS version, address width and idle hint");
    control(0); read_dtmcs(dtmcs);
    check(dtmcs == 32'h1071, "DTMCS read-only fields ignore a zero write");
    for (integer n = 0; n < 32; n++) if (n != 1 && n != 16 && n != 17) begin
      scan_ir(n); scan_dr(7'b1011011, 7, result);
      check(result[6:0] == 7'b0110110, "Unimplemented IR selects one-bit BYPASS");
    end
    for (integer mode = 0; mode < 2; mode++) begin
      zeroLatency = mode;
      for (integer n = 0; n < 9; n++) begin
        reg [6:0] address;
        address = n == 8 ? 127 : n == 0 ? 0 : 1 << (n - 1);
        access(1, address, 0);
        access(2, address, 32'h5a010203 ^ (32'h01010101 * n));
        access(1, address, 0);
      end
    end
    zeroLatency = 0;
    forcedStatus = 2; request(1, 5, 0); #(systemHalf * 60); idle(8); poll(result);
    check(result[1:0] == 2, "Failed response is reported");
    read_dtmcs(dtmcs); check(dtmcs[11:10] == 2, "Failed status is sticky in DTMCS");
    scan_dr(0, 41, result); check(result[1:0] == 2, "Failed status survives idle scans");
    sawStickyFailed = 1;
    beforeCount = accepted; beforeAddressWrites = writeCount[6];
    request(2, 6, 32'hffffffff); idle(32);
    check(accepted == beforeCount && writeCount[6] == beforeAddressWrites,
          "Sticky failure suppresses later writes");
    forcedStatus = 0; control(32'h10000); access(1, 6, 0);

    holdResponse = 1; beforeCount = accepted; beforeWrites = writes;
    beforeAddressWrites = writeCount[9]; beforeRejectedWrites = writeCount[10];
    request(2, 9, 32'hfeed1234); idle(64); scan_dr(0, 41, result);
    check(result[1:0] == 3, "Premature capture reports busy");
    read_dtmcs(dtmcs); check(dtmcs[11:10] == 3, "Busy status is sticky in DTMCS");
    sawStickyBusy = 1;
    request(2, 10, 32'hbad12345); control(32'h10000); scan_dr(0, 41, result);
    check(result[1:0] == 3, "DMI reset preserves the outstanding request");
    holdResponse = 0; idle(64); control(32'h10000); poll(result);
    check(result[1:0] == 0 && accepted == beforeCount + 1 && writes == beforeWrites + 1,
          "Busy scans do not duplicate writes");
    check(writeCount[9] == beforeAddressWrites + 1 &&
          writeCount[10] == beforeRejectedWrites,
          "DMI reset rejects replacement write and retains exactly one original write");

    for (integer kind = 0; kind < 3; kind++) preserve_request(kind, 20 + 2 * kind);
    for (integer kind = 0; kind < 3; kind++) preserve_response(kind, 32 + 2 * kind);

    beforeCount = accepted; beforeAddressWrites = writeCount[15];
    request(2, 15, 32'habc00003); #(systemHalf * 300);
    check(!requestReady, "Stopped TCK retains the bridge owner");
    idle(128); poll(result);
    check(result[1:0] == 0 && accepted == beforeCount + 1 &&
          writeCount[15] == beforeAddressWrites + 1,
          "Stopped TCK retains exactly one transaction");
    sawTckStop = 1;

    beforeCount = accepted; beforeAddressWrites = writeCount[16];
    systemRun = 0; #(systemHalf * 2);
    request(2, 16, 32'habc00004); idle(32); scan_dr(0, 41, result);
    check(result[1:0] == 3 && accepted == beforeCount,
          "Stopped system clock reports busy without acceptance");
    systemRun = 1; idle(128); control(32'h10000); poll(result); access(1, 16, 0);
    check(writeCount[16] == beforeAddressWrites + 1,
          "Stopped system clock does not replay a write");
    sawSystemStop = 1;

    check(accepted == 70 && completed == 70 && writes == 25,
          "Expected transactions complete without spurious or repeated writes");
    check(zeroResponses == 27 && delayedResponses == 43,
          "Expected zero-latency and delayed response counts");
    check(requestStallCycles != 0 && responseStallCycles != 0,
          "Both request and response backpressure executed");
    check(preservedRequests == 3 && preservedResponses == 3,
          "All DTM resets preserve request and response ownership");
    check(sawStickyBusy && sawStickyFailed && sawSystemStop && sawTckStop,
          "Sticky status and stopped-clock scenarios executed");
    $display("JTAG accepted=%0d completed=%0d writes=%0d requestStalls=%0d responseStalls=%0d",
             accepted, completed, writes, requestStallCycles, responseStallCycles);
    $display("JTAG coverage zero=%0d delayed=%0d preservedRequests=%0d preservedResponses=%0d",
             zeroResponses, delayedResponses, preservedRequests, preservedResponses);
    $display("PASS"); $finish;
  end
  initial begin #10000000; $fatal(1, "JTAG timeout"); end
endmodule
