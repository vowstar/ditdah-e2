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
    // Unconditional full-width identities, including inactive datapath states.
    mul_transition #(.LOW_BIT(1'b0)) polynomial_lsb0 (
        .clock(clock),
        .accumulator(dut.product),
        .multiplicand(dut.multiplicand),
        .remaining_high(dut.multiplier[31:1])
    );
    mul_transition #(.LOW_BIT(1'b1)) polynomial_lsb1 (
        .clock(clock),
        .accumulator(dut.product),
        .multiplicand(dut.multiplicand),
        .remaining_high(dut.multiplier[31:1])
    );

    wire [63:0] chain_total = dut.product + remaining_product;
    wire [63:0] chain_predicted_product = dut.product +
        (dut.multiplier[0] ? dut.multiplicand : 64'd0);
    wire [63:0] chain_predicted_multiplicand = {dut.multiplicand[62:0], 1'b0};
    wire [31:0] chain_predicted_multiplier = {1'b0, dut.multiplier[31:1]};
    wire [63:0] chain_predicted_total = chain_predicted_product +
        chain_predicted_multiplicand * {32'd0, chain_predicted_multiplier};
    wire chain_selected_owner = pending && owner_op == OPERATION && !OPERATION[2];
    logic [63:0] chain_previous_product, chain_previous_multiplicand;
    logic [31:0] chain_previous_multiplier, chain_previous_expected;
    logic [31:0] chain_previous_owner_left, chain_previous_owner_right;
    logic [2:0] chain_previous_owner_operation;
    logic [5:0] chain_previous_iteration;
    logic chain_previous_negative;
    logic chain_previous_owner, chain_previous_mul_step;
    logic chain_previous_mul_finish, chain_previous_mul_hold;
    wire chain_previous_left_signed = chain_previous_owner_operation == 1 ||
        chain_previous_owner_operation == 2 || chain_previous_owner_operation == 4 ||
        chain_previous_owner_operation == 6;
    wire chain_previous_right_signed = chain_previous_owner_operation == 1 ||
        chain_previous_owner_operation == 4 || chain_previous_owner_operation == 6;
    wire chain_previous_left_negative = chain_previous_left_signed && chain_previous_owner_left[31];
    wire chain_previous_right_negative = chain_previous_right_signed && chain_previous_owner_right[31];
    wire [31:0] chain_previous_left_magnitude = chain_previous_left_negative ?
        32'd0 - chain_previous_owner_left : chain_previous_owner_left;
    wire [31:0] chain_previous_right_magnitude = chain_previous_right_negative ?
        32'd0 - chain_previous_owner_right : chain_previous_owner_right;
    wire [63:0] chain_previous_reference = {32'd0, chain_previous_left_magnitude} *
        {32'd0, chain_previous_right_magnitude};
    wire [63:0] chain_previous_total = chain_previous_product +
        chain_previous_multiplicand * {32'd0, chain_previous_multiplier};
    wire [63:0] chain_previous_predicted_product = chain_previous_product +
        (chain_previous_multiplier[0] ? chain_previous_multiplicand : 64'd0);
    wire [63:0] chain_previous_predicted_multiplicand =
        {chain_previous_multiplicand[62:0], 1'b0};
    wire [31:0] chain_previous_predicted_multiplier = {1'b0, chain_previous_multiplier[31:1]};
    wire [63:0] chain_previous_predicted_total = chain_previous_predicted_product +
        chain_previous_predicted_multiplicand * {32'd0, chain_previous_predicted_multiplier};
    wire [63:0] chain_previous_corrected_product = chain_previous_negative ?
        64'd0 - chain_previous_product : chain_previous_product;

    always @(posedge clock) begin
        chain_variable_lsb_identity: assert(chain_predicted_total == chain_total);
        if (reset) begin
            chain_previous_product <= 0;
            chain_previous_multiplicand <= 0;
            chain_previous_multiplier <= 0;
            chain_previous_expected <= 0;
            chain_previous_owner_left <= 0;
            chain_previous_owner_right <= 0;
            chain_previous_owner_operation <= 0;
            chain_previous_iteration <= 0;
            chain_previous_negative <= 0;
            chain_previous_owner <= 0;
            chain_previous_mul_step <= 0;
            chain_previous_mul_finish <= 0;
            chain_previous_mul_hold <= 0;
        end else begin
            chain_previous_product <= dut.product;
            chain_previous_multiplicand <= dut.multiplicand;
            chain_previous_multiplier <= dut.multiplier;
            chain_previous_expected <= expected;
            chain_previous_owner_left <= owner_left;
            chain_previous_owner_right <= owner_right;
            chain_previous_owner_operation <= owner_op;
            chain_previous_iteration <= dut.iteration;
            chain_previous_negative <= dut.negative;
            chain_previous_owner <= !cancel && chain_selected_owner;
            chain_previous_mul_step <= !cancel && chain_selected_owner &&
                dut.active && dut.iteration < 32;
            chain_previous_mul_finish <= !cancel && chain_selected_owner &&
                dut.active && dut.iteration == 32;
            chain_previous_mul_hold <= !cancel && chain_selected_owner &&
                dut.valid && !response_ready;
        end

        if (history_valid && !reset && !cancel && chain_selected_owner) begin
            if (chain_previous_owner) begin
                chain_owner_operation_stable: assert(owner_op == chain_previous_owner_operation);
                chain_owner_left_stable: assert(owner_left == chain_previous_owner_left);
                chain_owner_right_stable: assert(owner_right == chain_previous_owner_right);
                chain_reference_stable: assert(magnitude_product == chain_previous_reference);
                chain_expected_stable: assert(expected == chain_previous_expected);
            end

            if (chain_previous_mul_step) begin
                chain_actual_step_active: assert(dut.active && !dut.valid);
                chain_actual_step_iteration: assert(dut.iteration == chain_previous_iteration + 6'd1);
                chain_actual_step_product: assert(dut.product == chain_previous_product +
                    (chain_previous_multiplier[0] ? chain_previous_multiplicand : 64'd0));
                chain_actual_step_multiplicand: assert(dut.multiplicand ==
                    {chain_previous_multiplicand[62:0], 1'b0});
                chain_actual_step_multiplier: assert(dut.multiplier ==
                    {1'b0, chain_previous_multiplier[31:1]});
                chain_actual_total_update: assert(chain_total == chain_previous_predicted_total);
                chain_sampled_identity: assert(chain_previous_predicted_total == chain_previous_total);
                chain_total_preserved: assert(chain_total == chain_previous_total);
            end

            if (dut.active && dut.iteration == 0) begin
                chain_initial_state: assert(dut.product == 0 &&
                    dut.multiplicand == {32'd0, owner_left_magnitude} &&
                    dut.multiplier == owner_right_magnitude);
                chain_initial_total: assert(chain_total == magnitude_product);
            end
            if (dut.active && dut.iteration == 32) begin
                chain_terminal_multiplier_zero: assert(dut.multiplier == 0);
                chain_terminal_total_is_product: assert(chain_total == dut.product);
            end
            if (chain_previous_mul_finish) begin
                chain_actual_finish_valid: assert(dut.valid && response_valid && !dut.active);
                if (OPERATION == 0)
                    chain_actual_finish_low: assert(response_bits == chain_previous_product[31:0]);
                else
                    chain_actual_finish_high: assert(response_bits == chain_previous_corrected_product[63:32]);
            end
            if (chain_previous_mul_hold) begin
                chain_blocked_total_stable: assert(chain_total == chain_previous_total);
            end
        end
    end

    always @(posedge clock) begin
        if (history_valid && !reset && !cancel && chain_selected_owner) begin
            if (chain_previous_owner) begin
                chain_owner_magnitudes_stable: assert(
                    owner_left_magnitude == chain_previous_left_magnitude &&
                    owner_right_magnitude == chain_previous_right_magnitude);
            end
            if (chain_previous_mul_hold) begin
                chain_actual_hold_product: assert(dut.product == chain_previous_product);
                chain_actual_hold_multiplicand: assert(dut.multiplicand == chain_previous_multiplicand);
                chain_actual_hold_multiplier: assert(dut.multiplier == chain_previous_multiplier);
            end
        end
    end


    logic first_proof_frame = 1'b1;
    always @(posedge clock) begin
        if (reset) first_proof_frame <= 1'b1;
        else first_proof_frame <= 1'b0;

        if (!reset && !cancel && chain_selected_owner && dut.active)
            epoch_active_has_predecessor: assert(history_valid &&
                (dut.iteration == 0 || (chain_previous_mul_step && chain_previous_owner)));
        if (history_valid && !reset && !previous_reset) begin
            snapshot_product_is_actual_past: assert(chain_previous_product == $past(dut.product));
            snapshot_multiplicand_is_actual_past: assert(chain_previous_multiplicand == $past(dut.multiplicand));
            snapshot_multiplier_is_actual_past: assert(chain_previous_multiplier == $past(dut.multiplier));
            snapshot_owner_left_is_actual_past: assert(chain_previous_owner_left == $past(owner_left));
            snapshot_owner_right_is_actual_past: assert(chain_previous_owner_right == $past(owner_right));
            snapshot_owner_operation_is_actual_past: assert(chain_previous_owner_operation == $past(owner_op));
        end
        if (history_valid && !reset) begin
            snapshot_mul_step_is_actual_past: assert(chain_previous_mul_step ==
                (!previous_reset && $past(!cancel && chain_selected_owner && dut.active && dut.iteration < 32)));
            snapshot_owner_is_actual_past: assert(chain_previous_owner ==
                (!previous_reset && $past(!cancel && chain_selected_owner)));
        end
        if (!reset && first_proof_frame)
            initial_frame_is_idle: assert(!pending && !dut.active);
        initial_frame_reached: cover(first_proof_frame && !reset);
    end


    always @(posedge clock) begin
        if (!reset && pending)
            captured_reference_matches_owner: assert(expected ==
                m_reference(OPERATION, owner_left, owner_right));
        if (!reset && !cancel && response_valid && owner_op == OPERATION)
            response_epoch_has_predecessor: assert(history_valid && pending &&
                (chain_previous_mul_finish || chain_previous_mul_hold));
        captured_reference_reached: cover(!reset && pending &&
            owner_op == OPERATION && owner_left[31] && owner_right[31]);
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
        if (!reset && !cancel && response_valid && owner_op == OPERATION) begin
            if (chain_previous_mul_finish)
                response_finish_has_actual_past_terminal_owner: assert(
                    chain_previous_owner && $past(!reset && !cancel && pending &&
                        dut.active && owner_op == OPERATION && dut.iteration == 32));
            if (chain_previous_mul_hold) begin
                response_hold_has_actual_past_goal: assert($past(!reset && !cancel &&
                    response_valid && owner_op == OPERATION));
                response_hold_data_matches_past: assert(response_bits == $past(response_bits));
                response_hold_expected_matches_past: assert(expected == $past(expected));
            end
        end
    end

    always @(posedge clock) begin
        if (history_valid && !reset && !previous_reset)
            snapshot_negative_is_actual_past: assert(
                chain_previous_negative == $past(dut.negative));
    end
endmodule
