// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

module md_math_bench #(
    parameter logic [2:0] OPERATION = 3'd0
) (
    input logic clock,
    input logic reset,
    input logic cancel,
    input logic request_valid,
    input logic [2:0] request_bits_operation,
    input logic [31:0] request_bits_left,
    input logic [31:0] request_bits_right,
    input logic response_ready
);
    wire request_ready, response_valid;
    wire [31:0] response_bits;

    DitDahE2MultiplyDivide dut (
        .clock(clock),
        .reset(reset),
        .cancel(cancel),
        .request_valid(request_valid),
        .request_ready(request_ready),
        .request_bits_operation(request_bits_operation),
        .request_bits_left(request_bits_left),
        .request_bits_right(request_bits_right),
        .response_valid(response_valid),
        .response_ready(response_ready),
        .response_bits(response_bits)
    );

    `include "reference.svh"


    logic first_cycle = 1'b1;
    logic history_valid = 1'b0;
    logic previous_reset, previous_cancel, previous_stall;
    logic [2:0] previous_operation;
    logic other_operation_completed;
    logic previous_response_valid, previous_response_ready;
    logic [31:0] previous_left, previous_right, previous_response;
    logic pending, response_seen;
    logic [31:0] expected;
    logic [5:0] age;
    logic [2:0] held_cycles;
    logic completed_once;
    wire accepted = !reset && !cancel && request_valid && request_ready;
    wire completed = !reset && !cancel && response_valid && response_ready;

    logic [31:0] owner_left, owner_right;
    logic [2:0] owner_op;
    wire owner_left_signed = owner_op == 1 || owner_op == 2 ||
                             owner_op == 4 || owner_op == 6;
    wire owner_right_signed = owner_op == 1 || owner_op == 4 || owner_op == 6;
    wire owner_left_negative = owner_left_signed && owner_left[31];
    wire owner_right_negative = owner_right_signed && owner_right[31];
    wire [31:0] owner_left_magnitude = owner_left_negative ? 32'd0 - owner_left : owner_left;
    wire [31:0] owner_right_magnitude = owner_right_negative ? 32'd0 - owner_right : owner_right;
    wire [63:0] magnitude_product = {32'd0, owner_left_magnitude} * {32'd0, owner_right_magnitude};
    wire [63:0] remaining_product = dut.multiplicand * {32'd0, dut.multiplier};
    wire [5:0] remaining_iterations = 6'd32 - dut.iteration;
    wire [31:0] quotient_mask = 32'hffffffff >> remaining_iterations;
    wire [31:0] quotient_partial = dut.quotient & quotient_mask;
    wire [31:0] dividend_prefix = owner_left_magnitude >> remaining_iterations;
    wire [64:0] division_sum = {32'd0, dut.remainder} +
                             ({33'd0, dut.divisor} * {33'd0, quotient_partial});

    always @(posedge clock) begin
        if (reset) begin
            owner_op <= 0;
            owner_left <= 0;
            owner_right <= 0;
        end else if (accepted) begin
            owner_op <= request_bits_operation;
            owner_left <= request_bits_left;
            owner_right <= request_bits_right;
        end
        if (!reset && !cancel && pending) begin
            owner_has_actual_state: assert(dut.active || dut.valid);
            owner_operation: assert(dut.operation == owner_op);
            owner_sign: assert(dut.negative == (owner_left_negative ^ owner_right_negative));
            owner_remainder_sign: assert(dut.remainderNegative == owner_left_negative);
            owner_zero_divisor: assert(dut.zeroDivisor == (owner_right == 0));
            owner_raw_dividend: assert(dut.dividend == owner_left);
            owner_divisor: assert(dut.divisor == owner_right_magnitude);
            iteration_in_range: assert(dut.iteration <= 32);
            if (dut.active && owner_op == OPERATION) begin
                if (!OPERATION[2]) begin
                    multiplier_tracks_remaining_bits: assert(dut.multiplier == (owner_right_magnitude >> dut.iteration));
                    multiplicand_tracks_iteration: assert(dut.multiplicand == ({32'd0, owner_left_magnitude} << dut.iteration));
                    multiplication_conservation: assert(dut.product + remaining_product == magnitude_product);
                    if (dut.iteration == 32)
                        multiplication_terminal: assert(dut.product == magnitude_product);
                end else begin
                    quotient_tracks_unprocessed_bits: assert((dut.quotient >> dut.iteration) ==
                        (owner_left_magnitude & (32'hffffffff >> dut.iteration)));
                    division_conservation: assert(division_sum == {33'd0, dividend_prefix});
                    remainder_fits_word: assert(!dut.remainder[32]);
                    if (owner_right_magnitude != 0)
                        remainder_below_divisor: assert(dut.remainder < {1'b0, dut.divisor});
                    if (dut.iteration == 32)
                        division_terminal: assert({32'd0, dut.remainder} +
                               ({33'd0, dut.divisor} * {33'd0, dut.quotient}) ==
                               {33'd0, owner_left_magnitude});
                end
            end
        end
    end


    always @(posedge clock) begin
        first_cycle <= 1'b0;
        history_valid <= 1'b1;
        previous_reset <= reset;
        previous_cancel <= cancel;
        previous_stall <= request_valid && !request_ready;
        previous_operation <= request_bits_operation;
        previous_left <= request_bits_left;
        previous_right <= request_bits_right;
        previous_response_valid <= response_valid;
        previous_response_ready <= response_ready;
        previous_response <= response_bits;

        if (first_cycle) begin
            initial_synchronous_reset: assume (reset);
        end
        if (reset) begin
            pending <= 1'b0;
            response_seen <= 1'b0;
            expected <= 0;
            age <= 0;
            held_cycles <= 0;
            completed_once <= 1'b0;
            other_operation_completed <= 0;
        end else begin
            // Reset or cancel can discard an offered producer transaction.
            if (!cancel && history_valid && !previous_reset && !previous_cancel && previous_stall) begin
                producer_keeps_valid: assume (request_valid);
                producer_keeps_operation: assume (request_bits_operation == previous_operation);
                producer_keeps_left: assume (request_bits_left == previous_left);
                producer_keeps_right: assume (request_bits_right == previous_right);
            end

            if (cancel) begin
                cancel_suppresses_request: assert (!request_ready);
                cancel_suppresses_response: assert (!response_valid);
                pending <= 1'b0;
                response_seen <= 1'b0;
                age <= 0;
                held_cycles <= 0;
            end else begin
                if (pending) begin
                    occupied_unit_rejects_new_request: assert (!request_ready);
                end else begin
                    idle_unit_accepts_requests: assert (request_ready);
                end
                if (accepted) begin
                    only_one_accepted_owner: assert (!pending);
                    pending <= 1'b1;
                    response_seen <= 1'b0;
                    expected <= m_reference(OPERATION, request_bits_left, request_bits_right);
                    age <= 1;
                    held_cycles <= 0;
                end
                if (response_valid) begin
                    response_has_accepted_owner: assert (pending);
                    if (owner_op == OPERATION)
                        arithmetic_matches_reference: assert (response_bits == expected);
                    response_seen <= 1'b1;
                    if (!response_ready && held_cycles != 7)
                        held_cycles <= held_cycles + 1'b1;
                end
                if (pending && !response_seen) begin
                    result_deadline_age: assert (age <= 34);
                    if (age == 34) begin
                        result_valid_by_34: assert (response_valid);
                    end
                    if (!response_valid)
                        age <= age + 1'b1;
                end
                if (history_valid && !previous_reset && !previous_cancel && previous_response_valid && !previous_response_ready) begin
                    blocked_result_keeps_valid: assert (response_valid);
                    blocked_result_keeps_value: assert (response_bits == previous_response);
                end
                if (completed) begin
                    pending <= 1'b0;
                    response_seen <= 1'b0;
                    held_cycles <= 0;
                    completed_once <= 1'b1;
                    if (owner_op != OPERATION) other_operation_completed <= 1;
                end
            end

            mixed_operation_completion: cover(completed && owner_op == OPERATION && other_operation_completed);
            request_reached: cover (accepted && request_bits_operation == OPERATION);
            high_operand_bits_reached: cover (accepted && request_bits_operation == OPERATION && request_bits_left[31] && request_bits_right[31]);
            zero_operand_reached: cover (accepted && request_bits_operation == OPERATION && request_bits_right == 0);
            result_reached: cover (completed && owner_op == OPERATION);
            cancellation_during_iteration_reached: cover (pending && owner_op == OPERATION && cancel && age == 17 && !response_seen);
            cancellation_at_deadline_reached: cover (pending && owner_op == OPERATION && cancel && age == 34 && !response_seen);
            blocked_result_cancellation_reached: cover (pending && owner_op == OPERATION && cancel && response_seen && held_cycles >= 3);
            held_result_completion_reached: cover (completed && owner_op == OPERATION && held_cycles >= 3);
            two_completions_reached: cover (completed && owner_op == OPERATION && completed_once);
        end
    end
    wire division_selected_owner = OPERATION[2] && pending && owner_op == OPERATION;
    logic division_previous_owner = 0, division_previous_accepted = 0;
    logic division_previous_step = 0, division_previous_finish = 0;
    logic [32:0] division_previous_remainder = 0;
    logic [31:0] division_previous_quotient = 0, division_previous_divisor = 0;
    logic [31:0] division_previous_owner_left = 0, division_previous_owner_right = 0;
    logic [2:0] division_previous_owner_operation = 0;
    logic [5:0] division_previous_iteration = 0;
    logic division_previous_zero_divisor = 0;

    wire division_previous_left_signed = division_previous_owner_operation == 1 ||
        division_previous_owner_operation == 2 || division_previous_owner_operation == 4 ||
        division_previous_owner_operation == 6;
    wire division_previous_right_signed = division_previous_owner_operation == 1 ||
        division_previous_owner_operation == 4 || division_previous_owner_operation == 6;
    wire division_previous_left_negative = division_previous_left_signed && division_previous_owner_left[31];
    wire division_previous_right_negative = division_previous_right_signed && division_previous_owner_right[31];
    wire division_previous_negative = division_previous_left_negative ^ division_previous_right_negative;
    wire [31:0] division_previous_left_magnitude = division_previous_left_negative ?
        32'd0 - division_previous_owner_left : division_previous_owner_left;
    wire [5:0] division_previous_remaining = 6'd32 - division_previous_iteration;
    wire [31:0] division_previous_mask = 32'hffffffff >> division_previous_remaining;
    wire [31:0] division_previous_partial = division_previous_quotient & division_previous_mask;
    wire [31:0] division_previous_prefix = division_previous_left_magnitude >> division_previous_remaining;
    wire [31:0] division_previous_next_prefix =
        division_previous_left_magnitude >> (6'd31 - division_previous_iteration);
    wire [32:0] division_previous_shifted =
        {division_previous_remainder[31:0], division_previous_quotient[31]};
    wire division_previous_decision = division_previous_shifted >= {1'b0, division_previous_divisor};
    wire [32:0] division_predicted_remainder = division_previous_decision ?
        division_previous_shifted - {1'b0, division_previous_divisor} : division_previous_shifted;
    wire [31:0] division_predicted_quotient =
        {division_previous_quotient[30:0], division_previous_decision};
    wire [31:0] division_predicted_partial =
        {division_previous_partial[30:0], division_previous_decision};
    wire [64:0] division_previous_sum = {32'd0, division_previous_remainder} +
        ({33'd0, division_previous_divisor} * {33'd0, division_previous_partial});
    wire [64:0] division_predicted_sum = {32'd0, division_predicted_remainder} +
        ({33'd0, division_previous_divisor} * {33'd0, division_predicted_partial});
    wire [64:0] division_doubled_previous_sum =
        (division_previous_sum << 1) + {64'd0, division_previous_quotient[31]};
    wire [64:0] division_doubled_previous_prefix =
        ({33'd0, division_previous_prefix} << 1) + {64'd0, division_previous_quotient[31]};

    div_transition #(.SUBTRACT(1'b0)) division_no_subtract (
        .clock(clock),
        .remainder_word(division_previous_remainder[31:0]),
        .divisor(division_previous_divisor),
        .quotient_partial(division_previous_partial[30:0]),
        .incoming_bit(division_previous_quotient[31])
    );
    div_transition #(.SUBTRACT(1'b1)) division_subtract (
        .clock(clock),
        .remainder_word(division_previous_remainder[31:0]),
        .divisor(division_previous_divisor),
        .quotient_partial(division_previous_partial[30:0]),
        .incoming_bit(division_previous_quotient[31])
    );

    always @(posedge clock) begin
        if (reset) begin
            division_previous_owner <= 0;
            division_previous_accepted <= 0;
            division_previous_step <= 0;
            division_previous_finish <= 0;
            division_previous_remainder <= 0;
            division_previous_quotient <= 0;
            division_previous_divisor <= 0;
            division_previous_owner_left <= 0;
            division_previous_owner_right <= 0;
            division_previous_owner_operation <= 0;
            division_previous_iteration <= 0;
            division_previous_zero_divisor <= 0;
        end else begin
            division_previous_owner <= !cancel && division_selected_owner;
            division_previous_accepted <= accepted && request_bits_operation == OPERATION && OPERATION[2];
            division_previous_step <= !cancel && division_selected_owner && dut.active && dut.iteration < 32;
            division_previous_finish <= !cancel && division_selected_owner && dut.active && dut.iteration == 32;
            if (!cancel && division_selected_owner) begin
                division_previous_remainder <= dut.remainder;
                division_previous_quotient <= dut.quotient;
                division_previous_divisor <= dut.divisor;
                division_previous_owner_left <= owner_left;
                division_previous_owner_right <= owner_right;
                division_previous_owner_operation <= owner_op;
                division_previous_iteration <= dut.iteration;
                division_previous_zero_divisor <= dut.zeroDivisor;
            end
        end

        if (!reset && !cancel && division_selected_owner)
            division_history_for_owner: assert(history_valid);
        if (history_valid && !reset && !cancel && division_selected_owner) begin
            division_epoch_continuity: assert(division_previous_owner || division_previous_accepted);
            if (division_previous_owner) begin
                division_owner_words_stable: assert(owner_left == division_previous_owner_left &&
                    owner_right == division_previous_owner_right && owner_op == division_previous_owner_operation);
            end
            if (dut.active && dut.iteration == 0) begin
                division_initial_state: assert(dut.remainder == 0 && dut.quotient == owner_left_magnitude &&
                    dut.divisor == owner_right_magnitude && quotient_partial == 0 && dividend_prefix == 0);
                division_initial_conservation: assert(division_sum == {33'd0, dividend_prefix});
            end
            if (dut.active && dut.iteration < 32)
                division_partial_fits_31_bits: assert(!quotient_partial[31]);

            if (division_previous_step) begin
                division_previous_remainder_fits: assert(!division_previous_remainder[32]);
                division_previous_partial_fits: assert(!division_previous_partial[31]);
                division_actual_control_step: assert(dut.active && !dut.valid &&
                    dut.iteration == division_previous_iteration + 6'd1);
                division_actual_remainder_step: assert(dut.remainder == division_predicted_remainder);
                division_actual_quotient_step: assert(dut.quotient == division_predicted_quotient);
                division_actual_divisor_stable: assert(dut.divisor == division_previous_divisor);
                division_mask_step: assert(quotient_partial == division_predicted_partial);
                division_next_source_bit: assert(division_previous_quotient[31] == division_previous_next_prefix[0]);
                division_prefix_step: assert({33'd0, dividend_prefix} == division_doubled_previous_prefix);
                division_old_sum_binding: assert(division_previous_sum == division_no_subtract.old_sum);
                division_polynomial_step: assert(division_predicted_sum == division_doubled_previous_sum);
                division_actual_sum_step: assert(division_sum == division_doubled_previous_sum);
            end
            if (dut.active && dut.iteration == 32) begin
                division_terminal_fields: assert(quotient_partial == dut.quotient && dividend_prefix == owner_left_magnitude);
                if (owner_right_magnitude != 0) begin
                    division_terminal_quotient_reference: assert(dut.quotient == owner_left_magnitude / owner_right_magnitude);
                    division_terminal_remainder_reference: assert(dut.remainder[31:0] == owner_left_magnitude % owner_right_magnitude);
                end else begin
                    division_zero_divisor_terminal: assert(dut.zeroDivisor && dut.remainder[31:0] == owner_left_magnitude);
                end
            end
            if (division_previous_finish) begin
                division_actual_finish_valid: assert(dut.valid && response_valid && !dut.active);
                division_actual_finish_value: assert(response_bits ==
                    (OPERATION[1] ?
                        (division_previous_zero_divisor ? division_previous_owner_left :
                            division_previous_left_negative ? 32'd0 - division_previous_remainder[31:0] :
                                division_previous_remainder[31:0]) :
                        (division_previous_zero_divisor ? 32'hffffffff :
                            division_previous_negative ? 32'd0 - division_previous_quotient :
                                division_previous_quotient)));
            end
        end
    end


    always @(posedge clock) begin
        if (!reset && !cancel && pending && dut.active &&
            OPERATION[2] && owner_op == OPERATION)
            division_remainder_iteration_bound:
                assert(dut.remainder < (33'd1 << dut.iteration));
    end

    logic division_first_proof_frame = 1'b1;
    always @(posedge clock) begin
        if (reset) division_first_proof_frame <= 1'b1;
        else division_first_proof_frame <= 1'b0;
        if (!reset && !cancel && division_selected_owner && dut.active)
            division_epoch_active_has_predecessor: assert(history_valid &&
                (dut.iteration == 0 || (division_previous_step && division_previous_owner)));
        if (history_valid && !reset && !previous_reset && division_previous_owner) begin
            division_snapshot_remainder: assert(division_previous_remainder == $past(dut.remainder));
            division_snapshot_quotient: assert(division_previous_quotient == $past(dut.quotient));
            division_snapshot_divisor: assert(division_previous_divisor == $past(dut.divisor));
            division_snapshot_owner_left: assert(division_previous_owner_left == $past(owner_left));
            division_snapshot_owner_right: assert(division_previous_owner_right == $past(owner_right));
            division_snapshot_owner_operation: assert(division_previous_owner_operation == $past(owner_op));
            division_snapshot_iteration: assert(division_previous_iteration == $past(dut.iteration));
            division_snapshot_zero_divisor: assert(division_previous_zero_divisor == $past(dut.zeroDivisor));
        end
        if (history_valid && !reset) begin
            division_snapshot_step_flag: assert(division_previous_step ==
                (!previous_reset && $past(!cancel && division_selected_owner &&
                    dut.active && dut.iteration < 32)));
            division_snapshot_owner_flag: assert(division_previous_owner ==
                (!previous_reset && $past(!cancel && division_selected_owner)));
            division_snapshot_accepted_flag: assert(division_previous_accepted ==
                (!previous_reset && $past(accepted && request_bits_operation == OPERATION && OPERATION[2])));
            division_snapshot_finish_flag: assert(division_previous_finish ==
                (!previous_reset && $past(!cancel && division_selected_owner &&
                    dut.active && dut.iteration == 32)));
        end
        if (!reset && division_first_proof_frame)
            division_initial_frame_is_idle: assert(!pending && !dut.active);
        division_initial_frame_reached: cover(division_first_proof_frame && !reset);
    end
    always @(posedge clock) begin
        if (!reset && pending)
            pending_capture_or_hold_predecessor: assert(history_valid &&
                !previous_reset && ($past(accepted) || $past(pending)));
        if (history_valid && !reset && !previous_reset) begin
            if ($past(accepted)) begin
                captured_expected_from_request: assert(expected ==
                    $past(m_reference(OPERATION, request_bits_left,
                        request_bits_right)));
                captured_owner_left_from_request: assert(owner_left ==
                    $past(request_bits_left));
                captured_owner_right_from_request: assert(owner_right ==
                    $past(request_bits_right));
            end else begin
                expected_without_accept_holds: assert(expected == $past(expected));
                owner_left_without_accept_holds: assert(owner_left == $past(owner_left));
                owner_right_without_accept_holds: assert(owner_right == $past(owner_right));
            end
        end
    end
    always @(posedge clock) begin
        division_selected_high_bits_result: cover(!reset && !cancel && response_valid &&
            owner_op == OPERATION && OPERATION[2] && owner_left[31] && owner_right[31]);
    end
    logic division_previous_response_hold = 1'b0;
    always @(posedge clock) begin
        if (reset) division_previous_response_hold <= 1'b0;
        else division_previous_response_hold <= !cancel && division_selected_owner &&
            response_valid && !response_ready;
        if (OPERATION[2] && !reset && !cancel && response_valid && owner_op == OPERATION)
            division_response_epoch_has_predecessor: assert(history_valid && pending &&
                (division_previous_finish || division_previous_response_hold));
        if (history_valid && !reset) begin
            division_snapshot_response_hold: assert(division_previous_response_hold ==
                (!previous_reset && $past(!cancel && division_selected_owner &&
                    response_valid && !response_ready)));
        end
        if (history_valid && !reset && !previous_reset) begin
            division_snapshot_previous_response: assert(previous_response == $past(response_bits));
            division_snapshot_previous_response_valid: assert(previous_response_valid == $past(response_valid));
            division_snapshot_previous_response_ready: assert(previous_response_ready == $past(response_ready));
            division_snapshot_previous_cancel: assert(previous_cancel == $past(cancel));
        end
        if (history_valid && !reset && !cancel && division_selected_owner && division_previous_response_hold)
            division_response_hold_precludes_accept: assert(!$past(accepted));

    end

endmodule
