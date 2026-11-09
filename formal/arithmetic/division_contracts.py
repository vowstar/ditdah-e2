# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Bind division proofs to sampled guards, typed words, and actual RTL ports."""

import re
from pathlib import Path

from . import facts, source, syntax

HEADER = """
module md_math_bench # ( parameter logic [ 2 : 0 ] OPERATION = OPERATION_VALUE )
(
 input logic clock ,
 input logic reset ,
 input logic cancel ,
 input logic request_valid ,
 input logic [ 2 : 0 ] request_bits_operation ,
 input logic [ 31 : 0 ] request_bits_left ,
 input logic [ 31 : 0 ] request_bits_right ,
 input logic response_ready ) ;
"""

DECLARATION_TEXT = """
wire request_ready, response_valid;
wire [31:0] response_bits;
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
wire accepted = ! reset && ! cancel && request_valid && request_ready;
wire completed = ! reset && ! cancel && response_valid && response_ready;
logic [31:0] owner_left, owner_right;
logic [2:0] owner_op;
wire owner_left_signed = owner_op == 1 || owner_op == 2 || owner_op == 4 || owner_op == 6;
wire owner_right_signed = owner_op == 1 || owner_op == 4 || owner_op == 6;
wire owner_left_negative = owner_left_signed && owner_left [31];
wire owner_right_negative = owner_right_signed && owner_right [31];
wire [31:0] owner_left_magnitude = owner_left_negative ? 32'd0 - owner_left:owner_left;
wire [31:0] owner_right_magnitude = owner_right_negative ? 32'd0 - owner_right:owner_right;
wire [63:0] magnitude_product = { 32'd0, owner_left_magnitude } * { 32'd0, owner_right_magnitude };
wire [63:0] remaining_product = dut.multiplicand * { 32'd0, dut.multiplier };
wire [5:0] remaining_iterations = 6'd32 - dut.iteration;
wire [31:0] quotient_mask = 32'hffffffff >> remaining_iterations;
wire [31:0] quotient_partial = dut.quotient & quotient_mask;
wire [31:0] dividend_prefix = owner_left_magnitude >> remaining_iterations;
wire [64:0] division_sum = { 32'd0, dut.remainder } + ({ 33'd0, dut.divisor } * { 33'd0, quotient_partial });
wire division_selected_owner = OPERATION [2] && pending && owner_op == OPERATION;
logic division_previous_owner = 0, division_previous_accepted = 0;
logic division_previous_step = 0, division_previous_finish = 0;
logic [32:0] division_previous_remainder = 0;
logic [31:0] division_previous_quotient = 0, division_previous_divisor = 0;
logic [31:0] division_previous_owner_left = 0, division_previous_owner_right = 0;
logic [2:0] division_previous_owner_operation = 0;
logic [5:0] division_previous_iteration = 0;
logic division_previous_zero_divisor = 0;
wire division_previous_left_signed = division_previous_owner_operation == 1 || division_previous_owner_operation == 2 || division_previous_owner_operation == 4 || division_previous_owner_operation == 6;
wire division_previous_right_signed = division_previous_owner_operation == 1 || division_previous_owner_operation == 4 || division_previous_owner_operation == 6;
wire division_previous_left_negative = division_previous_left_signed && division_previous_owner_left [31];
wire division_previous_right_negative = division_previous_right_signed && division_previous_owner_right [31];
wire division_previous_negative = division_previous_left_negative ^ division_previous_right_negative;
wire [31:0] division_previous_left_magnitude = division_previous_left_negative ? 32'd0 - division_previous_owner_left:division_previous_owner_left;
wire [5:0] division_previous_remaining = 6'd32 - division_previous_iteration;
wire [31:0] division_previous_mask = 32'hffffffff >> division_previous_remaining;
wire [31:0] division_previous_partial = division_previous_quotient & division_previous_mask;
wire [31:0] division_previous_prefix = division_previous_left_magnitude >> division_previous_remaining;
wire [31:0] division_previous_next_prefix = division_previous_left_magnitude >> (6'd31 - division_previous_iteration);
wire [32:0] division_previous_shifted = { division_previous_remainder [31:0], division_previous_quotient [31] };
wire division_previous_decision = division_previous_shifted >= { 1'b0, division_previous_divisor };
wire [32:0] division_predicted_remainder = division_previous_decision ? division_previous_shifted - { 1'b0, division_previous_divisor }:division_previous_shifted;
wire [31:0] division_predicted_quotient = { division_previous_quotient [30:0], division_previous_decision };
wire [31:0] division_predicted_partial = { division_previous_partial [30:0], division_previous_decision };
wire [64:0] division_previous_sum = { 32'd0, division_previous_remainder } + ({ 33'd0, division_previous_divisor } * { 33'd0, division_previous_partial });
wire [64:0] division_predicted_sum = { 32'd0, division_predicted_remainder } + ({ 33'd0, division_previous_divisor } * { 33'd0, division_predicted_partial });
wire [64:0] division_doubled_previous_sum = (division_previous_sum << 1) + { 64'd0, division_previous_quotient [31] };
wire [64:0] division_doubled_previous_prefix = ({ 33'd0, division_previous_prefix } << 1) + { 64'd0, division_previous_quotient [31] };
logic division_first_proof_frame = 1'b1;
logic division_previous_response_hold = 1'b0;
"""
DECLARATIONS = [
    " ".join(syntax.tokens(s + ";")) for s in DECLARATION_TEXT.split(";") if s.strip()
]

INSTANCE_TEXT = """
DitDahE2MultiplyDivide dut (. clock (clock),
    . reset (reset),
    . cancel (cancel),
    . request_valid (request_valid),
    . request_ready (request_ready),
    . request_bits_operation (request_bits_operation),
    . request_bits_left (request_bits_left),
    . request_bits_right (request_bits_right),
    . response_valid (response_valid),
    . response_ready (response_ready),
    . response_bits (response_bits));
div_transition # (. SUBTRACT (1'b0)) division_no_subtract (. clock (clock),
    . remainder_word (division_previous_remainder [31:0]),
    . divisor (division_previous_divisor),
    . quotient_partial (division_previous_partial [30:0]),
    . incoming_bit (division_previous_quotient [31]));
div_transition # (. SUBTRACT (1'b1)) division_subtract (. clock (clock),
    . remainder_word (division_previous_remainder [31:0]),
    . divisor (division_previous_divisor),
    . quotient_partial (division_previous_partial [30:0]),
    . incoming_bit (division_previous_quotient [31]));
"""
INSTANCES = [
    " ".join(syntax.tokens(s + ";")) for s in INSTANCE_TEXT.split(";") if s.strip()
]

OWNER = [("! reset && ! cancel && pending", True)]
MULTIPLY_ACTIVE = [
    ("! reset && ! cancel && pending", True),
    ("dut.active && owner_op == OPERATION", True),
    ("! OPERATION [2]", True),
]
MULTIPLY_TERMINAL = [
    ("! reset && ! cancel && pending", True),
    ("dut.active && owner_op == OPERATION", True),
    ("! OPERATION [2]", True),
    ("dut.iteration == 32", True),
]
DIVIDE_ACTIVE = [
    ("! reset && ! cancel && pending", True),
    ("dut.active && owner_op == OPERATION", True),
    ("! OPERATION [2]", False),
]
DIVIDE_NONZERO = [
    ("! reset && ! cancel && pending", True),
    ("dut.active && owner_op == OPERATION", True),
    ("! OPERATION [2]", False),
    ("owner_right_magnitude != 0", True),
]
DIVIDE_TERMINAL = [
    ("! reset && ! cancel && pending", True),
    ("dut.active && owner_op == OPERATION", True),
    ("! OPERATION [2]", False),
    ("dut.iteration == 32", True),
]
FIRST_CYCLE = [("first_cycle", True)]
PRODUCER_STALL = [
    ("reset", False),
    (
        "! cancel && history_valid && ! previous_reset && ! previous_cancel && previous_stall",
        True,
    ),
]
CANCEL = [("reset", False), ("cancel", True)]
OCCUPIED = [("reset", False), ("cancel", False), ("pending", True)]
IDLE = [("reset", False), ("cancel", False), ("pending", False)]
ACCEPTED = [("reset", False), ("cancel", False), ("accepted", True)]
RESPONSE = [("reset", False), ("cancel", False), ("response_valid", True)]
ORIGINAL_GOAL = [
    ("reset", False),
    ("cancel", False),
    ("response_valid", True),
    ("owner_op == OPERATION", True),
]
PENDING_RESULT = [
    ("reset", False),
    ("cancel", False),
    ("pending && ! response_seen", True),
]
DEADLINE = [
    ("reset", False),
    ("cancel", False),
    ("pending && ! response_seen", True),
    ("age == 34", True),
]
BLOCKED_RESPONSE = [
    ("reset", False),
    ("cancel", False),
    (
        (
            "history_valid && ! previous_reset && ! previous_cancel && previous_response_valid && ! "
            "previous_response_ready"
        ),
        True,
    ),
]
NO_RESET = [("reset", False)]
DIVISION_OWNER = [("! reset && ! cancel && division_selected_owner", True)]
DIVISION_HISTORY = [
    ("history_valid && ! reset && ! cancel && division_selected_owner", True)
]
PREVIOUS_OWNER = [
    ("history_valid && ! reset && ! cancel && division_selected_owner", True),
    ("division_previous_owner", True),
]
INITIAL_DIVISION = [
    ("history_valid && ! reset && ! cancel && division_selected_owner", True),
    ("dut.active && dut.iteration == 0", True),
]
ACTIVE_DIVISION = [
    ("history_valid && ! reset && ! cancel && division_selected_owner", True),
    ("dut.active && dut.iteration < 32", True),
]
PREVIOUS_STEP = [
    ("history_valid && ! reset && ! cancel && division_selected_owner", True),
    ("division_previous_step", True),
]
TERMINAL_DIVISION = [
    ("history_valid && ! reset && ! cancel && division_selected_owner", True),
    ("dut.active && dut.iteration == 32", True),
]
NONZERO_TERMINAL = [
    ("history_valid && ! reset && ! cancel && division_selected_owner", True),
    ("dut.active && dut.iteration == 32", True),
    ("owner_right_magnitude != 0", True),
]
ZERO_TERMINAL = [
    ("history_valid && ! reset && ! cancel && division_selected_owner", True),
    ("dut.active && dut.iteration == 32", True),
    ("owner_right_magnitude != 0", False),
]
PREVIOUS_FINISH = [
    ("history_valid && ! reset && ! cancel && division_selected_owner", True),
    ("division_previous_finish", True),
]
REMAINDER_BOUND = [
    (
        "! reset && ! cancel && pending && dut.active && OPERATION [2] && owner_op == OPERATION",
        True,
    )
]
ACTIVE_EPOCH = [("! reset && ! cancel && division_selected_owner && dut.active", True)]
OWNER_SNAPSHOT = [
    ("history_valid && ! reset && ! previous_reset && division_previous_owner", True)
]
FLAG_SNAPSHOT = [("history_valid && ! reset", True)]
FIRST_FRAME = [("! reset && division_first_proof_frame", True)]
ALWAYS = []
PENDING = [("! reset && pending", True)]
CAPTURE = [
    ("history_valid && ! reset && ! previous_reset", True),
    ("$past (accepted)", True),
]
HOLD = [
    ("history_valid && ! reset && ! previous_reset", True),
    ("$past (accepted)", False),
]
RESPONSE_EPOCH = [
    (
        "OPERATION [2] && ! reset && ! cancel && response_valid && owner_op == OPERATION",
        True,
    )
]
HISTORY = [("history_valid && ! reset && ! previous_reset", True)]
RESPONSE_HOLD = [
    (
        (
            "history_valid && ! reset && ! cancel && division_selected_owner && "
            "division_previous_response_hold"
        ),
        True,
    )
]

CONTRACTS = {}
for _kind, _guards, _claims in (
    ('assert', OWNER, {
        'owner_has_actual_state': 'dut.active || dut.valid',
        'owner_operation': 'dut.operation == owner_op',
        'owner_sign': 'dut.negative == (owner_left_negative ^ owner_right_negative)',
        'owner_remainder_sign': 'dut.remainderNegative == owner_left_negative',
        'owner_zero_divisor': 'dut.zeroDivisor == (owner_right == 0)',
        'owner_raw_dividend': 'dut.dividend == owner_left',
        'owner_divisor': 'dut.divisor == owner_right_magnitude',
        'iteration_in_range': 'dut.iteration <= 32',
    }),
    ('assert', MULTIPLY_ACTIVE, {
        'multiplier_tracks_remaining_bits': 'dut.multiplier == (owner_right_magnitude >> dut.iteration)',
        'multiplicand_tracks_iteration': "dut.multiplicand == ({ 32'd0, owner_left_magnitude } << dut.iteration)",
        'multiplication_conservation': 'dut.product + remaining_product == magnitude_product',
    }),
    ('assert', MULTIPLY_TERMINAL, {
        'multiplication_terminal': 'dut.product == magnitude_product',
    }),
    ('assert', DIVIDE_ACTIVE, {
        'quotient_tracks_unprocessed_bits': "(dut.quotient >> dut.iteration) == (owner_left_magnitude & (32'hffffffff >> dut.iteration))",
        'division_conservation': "division_sum == { 33'd0, dividend_prefix }",
        'remainder_fits_word': '! dut.remainder [32]',
    }),
    ('assert', DIVIDE_NONZERO, {
        'remainder_below_divisor': "dut.remainder < { 1'b0, dut.divisor }",
    }),
    ('assert', DIVIDE_TERMINAL, {
        'division_terminal': "{ 32'd0, dut.remainder } + ({ 33'd0, dut.divisor } * { 33'd0, dut.quotient }) == { 33'd0, owner_left_magnitude }",
    }),
    ('assume', FIRST_CYCLE, {
        'initial_synchronous_reset': 'reset',
    }),
    ('assume', PRODUCER_STALL, {
        'producer_keeps_valid': 'request_valid',
        'producer_keeps_operation': 'request_bits_operation == previous_operation',
        'producer_keeps_left': 'request_bits_left == previous_left',
        'producer_keeps_right': 'request_bits_right == previous_right',
    }),
    ('assert', CANCEL, {
        'cancel_suppresses_request': '! request_ready',
        'cancel_suppresses_response': '! response_valid',
    }),
    ('assert', OCCUPIED, {
        'occupied_unit_rejects_new_request': '! request_ready',
    }),
    ('assert', IDLE, {
        'idle_unit_accepts_requests': 'request_ready',
    }),
    ('assert', ACCEPTED, {
        'only_one_accepted_owner': '! pending',
    }),
    ('assert', RESPONSE, {
        'response_has_accepted_owner': 'pending',
    }),
    ('assert', ORIGINAL_GOAL, {
        'arithmetic_matches_reference': 'response_bits == expected',
    }),
    ('assert', PENDING_RESULT, {
        'result_deadline_age': 'age <= 34',
    }),
    ('assert', DEADLINE, {
        'result_valid_by_34': 'response_valid',
    }),
    ('assert', BLOCKED_RESPONSE, {
        'blocked_result_keeps_valid': 'response_valid',
        'blocked_result_keeps_value': 'response_bits == previous_response',
    }),
    ('cover', NO_RESET, {
        'mixed_operation_completion': 'completed && owner_op == OPERATION && other_operation_completed',
        'request_reached': 'accepted && request_bits_operation == OPERATION',
        'high_operand_bits_reached': 'accepted && request_bits_operation == OPERATION && request_bits_left [31] && request_bits_right [31]',
        'zero_operand_reached': 'accepted && request_bits_operation == OPERATION && request_bits_right == 0',
        'result_reached': 'completed && owner_op == OPERATION',
        'cancellation_during_iteration_reached': 'pending && owner_op == OPERATION && cancel && age == 17 && ! response_seen',
        'cancellation_at_deadline_reached': 'pending && owner_op == OPERATION && cancel && age == 34 && ! response_seen',
        'blocked_result_cancellation_reached': 'pending && owner_op == OPERATION && cancel && response_seen && held_cycles >= 3',
        'held_result_completion_reached': 'completed && owner_op == OPERATION && held_cycles >= 3',
        'two_completions_reached': 'completed && owner_op == OPERATION && completed_once',
    }),
    ('assert', DIVISION_OWNER, {
        'division_history_for_owner': 'history_valid',
    }),
    ('assert', DIVISION_HISTORY, {
        'division_epoch_continuity': 'division_previous_owner || division_previous_accepted',
    }),
    ('assert', PREVIOUS_OWNER, {
        'division_owner_words_stable': 'owner_left == division_previous_owner_left && owner_right == division_previous_owner_right && owner_op == division_previous_owner_operation',
    }),
    ('assert', INITIAL_DIVISION, {
        'division_initial_state': 'dut.remainder == 0 && dut.quotient == owner_left_magnitude && dut.divisor == owner_right_magnitude && quotient_partial == 0 && dividend_prefix == 0',
        'division_initial_conservation': "division_sum == { 33'd0, dividend_prefix }",
    }),
    ('assert', ACTIVE_DIVISION, {
        'division_partial_fits_31_bits': '! quotient_partial [31]',
    }),
    ('assert', PREVIOUS_STEP, {
        'division_previous_remainder_fits': '! division_previous_remainder [32]',
        'division_previous_partial_fits': '! division_previous_partial [31]',
        'division_actual_control_step': "dut.active && ! dut.valid && dut.iteration == division_previous_iteration + 6'd1",
        'division_actual_remainder_step': 'dut.remainder == division_predicted_remainder',
        'division_actual_quotient_step': 'dut.quotient == division_predicted_quotient',
        'division_actual_divisor_stable': 'dut.divisor == division_previous_divisor',
        'division_mask_step': 'quotient_partial == division_predicted_partial',
        'division_next_source_bit': 'division_previous_quotient [31] == division_previous_next_prefix [0]',
        'division_prefix_step': "{ 33'd0, dividend_prefix } == division_doubled_previous_prefix",
        'division_old_sum_binding': 'division_previous_sum == division_no_subtract.old_sum',
        'division_polynomial_step': 'division_predicted_sum == division_doubled_previous_sum',
        'division_actual_sum_step': 'division_sum == division_doubled_previous_sum',
    }),
    ('assert', TERMINAL_DIVISION, {
        'division_terminal_fields': 'quotient_partial == dut.quotient && dividend_prefix == owner_left_magnitude',
    }),
    ('assert', NONZERO_TERMINAL, {
        'division_terminal_quotient_reference': 'dut.quotient == owner_left_magnitude / owner_right_magnitude',
        'division_terminal_remainder_reference': 'dut.remainder [31:0] == owner_left_magnitude % owner_right_magnitude',
    }),
    ('assert', ZERO_TERMINAL, {
        'division_zero_divisor_terminal': 'dut.zeroDivisor && dut.remainder [31:0] == owner_left_magnitude',
    }),
    ('assert', PREVIOUS_FINISH, {
        'division_actual_finish_valid': 'dut.valid && response_valid && ! dut.active',
        'division_actual_finish_value': "response_bits == (OPERATION [1] ? (division_previous_zero_divisor ? division_previous_owner_left:division_previous_left_negative ? 32'd0 - division_previous_remainder [31:0]:division_previous_remainder [31:0]):(division_previous_zero_divisor ? 32'hffffffff:division_previous_negative ? 32'd0 - division_previous_quotient:division_previous_quotient))",
    }),
    ('assert', REMAINDER_BOUND, {
        'division_remainder_iteration_bound': "dut.remainder < (33'd1 << dut.iteration)",
    }),
    ('assert', ACTIVE_EPOCH, {
        'division_epoch_active_has_predecessor': 'history_valid && (dut.iteration == 0 || (division_previous_step && division_previous_owner))',
    }),
    ('assert', OWNER_SNAPSHOT, {
        'division_snapshot_remainder': 'division_previous_remainder == $past (dut.remainder)',
        'division_snapshot_quotient': 'division_previous_quotient == $past (dut.quotient)',
        'division_snapshot_divisor': 'division_previous_divisor == $past (dut.divisor)',
        'division_snapshot_owner_left': 'division_previous_owner_left == $past (owner_left)',
        'division_snapshot_owner_right': 'division_previous_owner_right == $past (owner_right)',
        'division_snapshot_owner_operation': 'division_previous_owner_operation == $past (owner_op)',
        'division_snapshot_iteration': 'division_previous_iteration == $past (dut.iteration)',
        'division_snapshot_zero_divisor': 'division_previous_zero_divisor == $past (dut.zeroDivisor)',
    }),
    ('assert', FLAG_SNAPSHOT, {
        'division_snapshot_step_flag': 'division_previous_step == (! previous_reset && $past (! cancel && division_selected_owner && dut.active && dut.iteration < 32))',
        'division_snapshot_owner_flag': 'division_previous_owner == (! previous_reset && $past (! cancel && division_selected_owner))',
        'division_snapshot_accepted_flag': 'division_previous_accepted == (! previous_reset && $past (accepted && request_bits_operation == OPERATION && OPERATION [2]))',
        'division_snapshot_finish_flag': 'division_previous_finish == (! previous_reset && $past (! cancel && division_selected_owner && dut.active && dut.iteration == 32))',
    }),
    ('assert', FIRST_FRAME, {
        'division_initial_frame_is_idle': '! pending && ! dut.active',
    }),
    ('cover', ALWAYS, {
        'division_initial_frame_reached': 'division_first_proof_frame && ! reset',
    }),
    ('assert', PENDING, {
        'pending_capture_or_hold_predecessor': 'history_valid && ! previous_reset && ($past (accepted) || $past (pending))',
    }),
    ('assert', CAPTURE, {
        'captured_expected_from_request': 'expected == $past (m_reference (OPERATION, request_bits_left, request_bits_right))',
        'captured_owner_left_from_request': 'owner_left == $past (request_bits_left)',
        'captured_owner_right_from_request': 'owner_right == $past (request_bits_right)',
    }),
    ('assert', HOLD, {
        'expected_without_accept_holds': 'expected == $past (expected)',
        'owner_left_without_accept_holds': 'owner_left == $past (owner_left)',
        'owner_right_without_accept_holds': 'owner_right == $past (owner_right)',
    }),
    ('cover', ALWAYS, {
        'division_selected_high_bits_result': '! reset && ! cancel && response_valid && owner_op == OPERATION && OPERATION [2] && owner_left [31] && owner_right [31]',
    }),
    ('assert', RESPONSE_EPOCH, {
        'division_response_epoch_has_predecessor': 'history_valid && pending && (division_previous_finish || division_previous_response_hold)',
    }),
    ('assert', FLAG_SNAPSHOT, {
        'division_snapshot_response_hold': 'division_previous_response_hold == (! previous_reset && $past (! cancel && division_selected_owner && response_valid && ! response_ready))',
    }),
    ('assert', HISTORY, {
        'division_snapshot_previous_response': 'previous_response == $past (response_bits)',
        'division_snapshot_previous_response_valid': 'previous_response_valid == $past (response_valid)',
        'division_snapshot_previous_response_ready': 'previous_response_ready == $past (response_ready)',
        'division_snapshot_previous_cancel': 'previous_cancel == $past (cancel)',
    }),
    ('assert', RESPONSE_HOLD, {
        'division_response_hold_precludes_accept': '! $past (accepted)',
    }),
):
    for _label, _body in _claims.items():
        CONTRACTS[_label] = (_kind, _guards, _body)

DRIVER_GUARDS = [
    [('reset', True)],
    [('reset', False), ('accepted', True)],
    [],
    [('reset', False), ('cancel', True)],
    [('reset', False), ('cancel', False), ('accepted', True)],
    [('reset', False), ('cancel', False), ('response_valid', True)],
    [('reset', False), ('cancel', False), ('response_valid', True), ('! response_ready && held_cycles != 7', True)],
    [('reset', False), ('cancel', False), ('pending && ! response_seen', True), ('! response_valid', True)],
    [('reset', False), ('cancel', False), ('completed', True)],
    [('reset', False), ('cancel', False), ('completed', True), ('owner_op != OPERATION', True)],
    [('reset', False)],
    [('reset', False), ('! cancel && division_selected_owner', True)],
]
DRIVER_ASSIGNMENTS = [
    (0, 'owner_op <= 0;'),
    (0, 'owner_left <= 0;'),
    (0, 'owner_right <= 0;'),
    (1, 'owner_op <= request_bits_operation;'),
    (1, 'owner_left <= request_bits_left;'),
    (1, 'owner_right <= request_bits_right;'),
    (2, "first_cycle <= 1'b0;"),
    (2, "history_valid <= 1'b1;"),
    (2, 'previous_reset <= reset;'),
    (2, 'previous_cancel <= cancel;'),
    (2, 'previous_stall <= request_valid && ! request_ready;'),
    (2, 'previous_operation <= request_bits_operation;'),
    (2, 'previous_left <= request_bits_left;'),
    (2, 'previous_right <= request_bits_right;'),
    (2, 'previous_response_valid <= response_valid;'),
    (2, 'previous_response_ready <= response_ready;'),
    (2, 'previous_response <= response_bits;'),
    (0, "pending <= 1'b0;"),
    (0, "response_seen <= 1'b0;"),
    (0, 'expected <= 0;'),
    (0, 'age <= 0;'),
    (0, 'held_cycles <= 0;'),
    (0, "completed_once <= 1'b0;"),
    (0, 'other_operation_completed <= 0;'),
    (3, "pending <= 1'b0;"),
    (3, "response_seen <= 1'b0;"),
    (3, 'age <= 0;'),
    (3, 'held_cycles <= 0;'),
    (4, "pending <= 1'b1;"),
    (4, "response_seen <= 1'b0;"),
    (4, 'expected <= m_reference (OPERATION, request_bits_left, request_bits_right);'),
    (4, 'age <= 1;'),
    (4, 'held_cycles <= 0;'),
    (5, "response_seen <= 1'b1;"),
    (6, "held_cycles <= held_cycles + 1'b1;"),
    (7, "age <= age + 1'b1;"),
    (8, "pending <= 1'b0;"),
    (8, "response_seen <= 1'b0;"),
    (8, 'held_cycles <= 0;'),
    (8, "completed_once <= 1'b1;"),
    (9, 'other_operation_completed <= 1;'),
    (0, 'division_previous_owner <= 0;'),
    (0, 'division_previous_accepted <= 0;'),
    (0, 'division_previous_step <= 0;'),
    (0, 'division_previous_finish <= 0;'),
    (0, 'division_previous_remainder <= 0;'),
    (0, 'division_previous_quotient <= 0;'),
    (0, 'division_previous_divisor <= 0;'),
    (0, 'division_previous_owner_left <= 0;'),
    (0, 'division_previous_owner_right <= 0;'),
    (0, 'division_previous_owner_operation <= 0;'),
    (0, 'division_previous_iteration <= 0;'),
    (0, 'division_previous_zero_divisor <= 0;'),
    (10, 'division_previous_owner <= ! cancel && division_selected_owner;'),
    (10, 'division_previous_accepted <= accepted && request_bits_operation == OPERATION && OPERATION [2];'),
    (10, 'division_previous_step <= ! cancel && division_selected_owner && dut.active && dut.iteration < 32;'),
    (10, 'division_previous_finish <= ! cancel && division_selected_owner && dut.active && dut.iteration == 32;'),
    (11, 'division_previous_remainder <= dut.remainder;'),
    (11, 'division_previous_quotient <= dut.quotient;'),
    (11, 'division_previous_divisor <= dut.divisor;'),
    (11, 'division_previous_owner_left <= owner_left;'),
    (11, 'division_previous_owner_right <= owner_right;'),
    (11, 'division_previous_owner_operation <= owner_op;'),
    (11, 'division_previous_iteration <= dut.iteration;'),
    (11, 'division_previous_zero_divisor <= dut.zeroDivisor;'),
    (0, "division_first_proof_frame <= 1'b1;"),
    (10, "division_first_proof_frame <= 1'b0;"),
    (0, "division_previous_response_hold <= 1'b0;"),
    (10, 'division_previous_response_hold <= ! cancel && division_selected_owner && response_valid && ! response_ready;'),
]
DRIVERS = [
    (
        "posedge clock",
        [(" ".join(syntax.tokens(s)), p) for s, p in DRIVER_GUARDS[i]],
        " ".join(syntax.tokens(body)),
    )
    for i, body in DRIVER_ASSIGNMENTS
]

TRANSITION = """
// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT

module div_transition #(
    parameter bit SUBTRACT = 1'b0
) (
    input logic clock,
    input logic [31:0] remainder_word,
    input logic [31:0] divisor,
    input logic [30:0] quotient_partial,
    input logic incoming_bit
);
    wire [32:0] shifted = {remainder_word, incoming_bit};
    wire subtraction_defined = shifted >= {1'b0, divisor};
    wire [32:0] next_remainder = SUBTRACT ?
        shifted - {1'b0, divisor} : shifted;
    wire [31:0] next_quotient_partial = {quotient_partial, SUBTRACT};
    wire [64:0] old_sum = {33'd0, remainder_word} +
        ({33'd0, divisor} * {34'd0, quotient_partial});
    wire [64:0] next_sum = {32'd0, next_remainder} +
        ({33'd0, divisor} * {33'd0, next_quotient_partial});
    wire [64:0] doubled_sum_with_bit = (old_sum << 1) + {64'd0, incoming_bit};

    // The subtracting branch is conditional, rather than an input assumption.
    always @(posedge clock) begin
        if (!SUBTRACT || subtraction_defined)
            exact_polynomial_transition: assert(next_sum == doubled_sum_with_bit);
    end
endmodule

module div_transition_nosubtract (
    input logic clock,
    input logic [31:0] remainder_word,
    input logic [31:0] divisor,
    input logic [30:0] quotient_partial,
    input logic incoming_bit
);
    div_transition #(.SUBTRACT(1'b0)) lemma(.*);
endmodule

module div_transition_subtract (
    input logic clock,
    input logic [31:0] remainder_word,
    input logic [31:0] divisor,
    input logic [30:0] quotient_partial,
    input logic incoming_bit
);
    div_transition #(.SUBTRACT(1'b1)) lemma(.*);
endmodule
"""


def _end_statement(ts, pos):
    depth = 0
    while not (ts[pos] == ";" and depth == 0):
        if ts[pos] in ("(", "[", "{"):
            depth += 1
        if ts[pos] in (")", "]", "}"):
            depth -= 1
        pos += 1
    return pos + 1


def _scaffold(text, operation):
    function = source.reference(text)
    ts = syntax.tokens(text.replace(function, ""))
    end = _end_statement(ts, 0)
    header = ts[:end]
    parameter = "3'd" + str(operation)
    if header.count(parameter) != 1:
        raise ValueError("Division parameter differs from the native configuration")
    header[header.index(parameter)] = "OPERATION_VALUE"
    if header != syntax.tokens(HEADER):
        raise ValueError("Division input widths or module interface changed")
    declarations, instances, drivers = [], [], []

    def statement(pos, guards, clock):
        if ts[pos] == "begin":
            pos += 1
            while ts[pos] != "end":
                pos = statement(pos, guards, clock)
            return pos + 1
        if ts[pos] == "if":
            stop = syntax.matching(ts, pos + 1)
            condition = ts[pos + 2 : stop - 1]
            pos = statement(stop, guards + [(condition, True)], clock)
            if ts[pos] == "else":
                pos = statement(pos + 1, guards + [(condition, False)], clock)
            return pos
        stop = _end_statement(ts, pos)
        if ts[pos + 1 : pos + 3] not in (
            [":", "assert"],
            [":", "assume"],
            [":", "cover"],
        ):
            if stop - pos < 4 or ts[pos + 1] not in ("<=", "="):
                raise ValueError("Division observer contains an unsupported statement")
            drivers.append(
                (
                    " ".join(clock),
                    [(" ".join(g), p) for g, p in guards],
                    " ".join(ts[pos:stop]),
                )
            )
        return stop

    pos = end
    while ts[pos] != "endmodule":
        if ts[pos] == "always":
            if ts[pos + 1 : pos + 3] != ["@", "("]:
                raise ValueError("Division observer has an unsupported clock")
            stop = syntax.matching(ts, pos + 2)
            pos = statement(stop, [], ts[pos + 3 : stop - 1])
        else:
            stop = _end_statement(ts, pos)
            entry = " ".join(ts[pos:stop])
            (declarations if ts[pos] in ("logic", "wire") else instances).append(entry)
            pos = stop
    if pos != len(ts) - 1:
        raise ValueError("Division source contains an extra module")
    if declarations != DECLARATIONS:
        raise ValueError("Division word widths, definitions, or initial values changed")
    if instances != INSTANCES:
        raise ValueError("Division DUT or transition wiring changed")
    if drivers != DRIVERS:
        raise ValueError("Division observer drivers or sampled guards changed")
    return {"declarations": declarations, "instances": instances, "drivers": drivers}


RTL_PORTS = {
    "clock": ("input", 1),
    "reset": ("input", 1),
    "cancel": ("input", 1),
    "request_valid": ("input", 1),
    "request_ready": ("output", 1),
    "request_bits_operation": ("input", 3),
    "request_bits_left": ("input", 32),
    "request_bits_right": ("input", 32),
    "response_valid": ("output", 1),
    "response_ready": ("input", 1),
    "response_bits": ("output", 32),
}


def _rtl_interface(text):
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.DOTALL)
    if len(re.findall(r"\bmodule\b", clean)) != 1:
        raise ValueError("Division RTL module inventory changed")
    match = re.search(
        r"\bmodule\s+DitDahE2MultiplyDivide\s*\((.*?)\);", clean, re.DOTALL
    )
    if not match:
        raise ValueError("Division RTL identity changed")
    ports = {}
    direction, width = None, None
    for declaration in match[1].split(","):
        declaration = declaration.strip()
        new = re.fullmatch(
            r"(input|output)\s+(?:\[(\d+):(\d+)\]\s+)?(\w+)", declaration
        )
        if new:
            direction, high, low, name = new.groups()
            width = int(high) - int(low) + 1 if high else 1
        elif re.fullmatch(r"\w+", declaration) and direction:
            name = declaration
        else:
            raise ValueError("Division RTL has an unsupported port declaration")
        if name in ports:
            raise ValueError("Division RTL has a duplicate port")
        ports[name] = (direction, width)
    expected = RTL_PORTS
    if ports != expected:
        raise ValueError("Division RTL port widths differ from RV32")
    return {name: list(value) for name, value in ports.items()}


def required_native_labels(operation):
    if type(operation) is not int or operation not in (4, 5, 6, 7):
        raise ValueError("Division operation is invalid")
    return tuple(name for name, _ in facts.goals(operation))


def bind_division(source_text, dut_text, operation):
    required = required_native_labels(operation)
    parsed = syntax.properties(source_text)
    if set(parsed) != set(CONTRACTS):
        raise ValueError("Division property inventory changed")
    checked = {}
    for label, (kind, guards, body) in CONTRACTS.items():
        expected = {
            "kind": kind,
            "clock": syntax.tokens("posedge clock"),
            "body": syntax.tokens(body),
            "guards": [{"tokens": syntax.tokens(g), "positive": p} for g, p in guards],
        }
        if parsed[label] != expected:
            raise ValueError("Division source contract changed: " + label)
        checked[label] = expected
    if sum(row["kind"] == "assume" for row in parsed.values()) != 5:
        raise ValueError("Division input assumptions changed")
    scaffold = _scaffold(source_text, operation)
    transition = Path(__file__).with_name("divide_step.sv").read_text()
    if syntax.tokens(transition) != syntax.tokens(TRANSITION):
        raise ValueError("Division polynomial transition contract changed")
    return {
        "operation": operation,
        "sourceSha256": source.digest(source_text.encode()),
        "dutSha256": source.digest(dut_text.encode()),
        "contracts": checked,
        "definitions": scaffold,
        "ports": _rtl_interface(dut_text),
        "transitionSha256": source.digest(transition.encode()),
        "requiredNativeLabels": list(required),
        "assumptions": [
            name for name, row in parsed.items() if row["kind"] == "assume"
        ],
        "operandBitsEach": 32,
        "actualOperationBits": 3,
        "guard": "!reset && !cancel && response_valid && owner_op == OPERATION",
        "referenceFunctionSha256": source.REFERENCE_HASH,
    }
