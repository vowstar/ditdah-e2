// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
module branch_prediction(input clock);
  reg reset = 1;
  always @(posedge clock) reset <= 0;
  (* anyseq *) reg [31:0] fetchPc, learnPc, learnTarget, executeNextPc;
  (* anyseq *) reg fetchMachine, fetchFault, fetchAccepted, learn, learnMachine, executeAccepted, clear;
  wire predict, executePredicted, correction;
  wire [31:0] target;
  DitDahE2BranchPrediction dut(.*);
  reg known = 0, pending = 0;
  reg replaced = 0;
  reg [64:0] record;
  reg [31:0] expected_target;
  wire match = known && record[64:33] == fetchPc && record[0] == fetchMachine && !fetchFault;
  always @(posedge clock) begin
    if (reset) begin
      known <= 0;
      pending <= 0;
      replaced <= 0;
    end else begin
      assert(predict == match);
      if (match) assert(target == record[32:1]);
      assert(executePredicted == pending);
      assert(!correction || pending);
      if (pending && expected_target != executeNextPc) assert(correction);
      if (!replaced) assert(correction == (pending && expected_target != executeNextPc));
      if (pending && !replaced) assert(expected_target == record[32:1]);
      if (pending && learn && learnTarget != record[32:1]) replaced <= 1;
      if (executeAccepted) begin
        pending <= 0;
        replaced <= 0;
      end
      if (fetchAccepted) begin
        pending <= match;
        if (match) expected_target <= record[32:1];
        replaced <= match && learn && learnTarget != record[32:1];
      end
      if (executeAccepted && correction && !learn) known <= 0;
      if (learn) begin
        known <= 1;
        record <= {learnPc, learnTarget, learnMachine};
      end
      if (clear) begin
        known <= 0;
        pending <= 0;
        replaced <= 0;
      end
      cover(predict && fetchMachine);
      cover(predict && !fetchMachine);
      cover(known && record[64:33] == fetchPc && record[0] != fetchMachine && !predict);
      cover(correction && executeAccepted);
      cover(pending && !correction && executeAccepted);
      cover(clear && pending);
      cover(learn && fetchAccepted && predict && learnTarget != target);
      cover(fetchAccepted && executeAccepted && predict);
      cover(known && fetchFault && !predict);
      cover(pending && replaced && expected_target == executeNextPc && correction && executeAccepted);
      cover(pending && replaced && expected_target != executeNextPc && record[32:1] == executeNextPc && correction);
      cover(pending && replaced && learn && learnTarget == expected_target);
      cover(learn && fetchAccepted && executeAccepted && predict && learnTarget != target);
      cover(pending && replaced && clear);
    end
  end
endmodule
