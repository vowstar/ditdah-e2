# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exact sampled contracts used by the multiplication composition rules."""

import hashlib
import json
import re
from . import source, syntax

CONTRACTS = (
    ('owner_has_actual_state', 'assert', [('! reset && ! cancel && pending', True)],
     'dut.active || dut.valid'),
    ('owner_operation', 'assert', [('! reset && ! cancel && pending', True)],
     'dut.operation == owner_op'),
    ('owner_sign', 'assert', [('! reset && ! cancel && pending', True)],
     'dut.negative == ( owner_left_negative ^ owner_right_negative )'),
    ('owner_remainder_sign', 'assert', [('! reset && ! cancel && pending', True)],
     'dut.remainderNegative == owner_left_negative'),
    ('owner_zero_divisor', 'assert', [('! reset && ! cancel && pending', True)],
     'dut.zeroDivisor == ( owner_right == 0 )'),
    ('owner_raw_dividend', 'assert', [('! reset && ! cancel && pending', True)],
     'dut.dividend == owner_left'),
    ('owner_divisor', 'assert', [('! reset && ! cancel && pending', True)],
     'dut.divisor == owner_right_magnitude'),
    ('iteration_in_range', 'assert', [('! reset && ! cancel && pending', True)],
     'dut.iteration <= 32'),
    ('multiplier_tracks_remaining_bits', 'assert', [('! reset && ! cancel && pending', True), ('dut.active && owner_op == OPERATION', True), ('! OPERATION [ 2 ]', True)],
     'dut.multiplier == ( owner_right_magnitude >> dut.iteration )'),
    ('multiplicand_tracks_iteration', 'assert', [('! reset && ! cancel && pending', True), ('dut.active && owner_op == OPERATION', True), ('! OPERATION [ 2 ]', True)],
     "dut.multiplicand == ( { 32'd0 , owner_left_magnitude } << dut.iteration )"),
    ('multiplication_conservation', 'assert', [('! reset && ! cancel && pending', True), ('dut.active && owner_op == OPERATION', True), ('! OPERATION [ 2 ]', True)],
     'dut.product + remaining_product == magnitude_product'),
    ('multiplication_terminal', 'assert', [('! reset && ! cancel && pending', True), ('dut.active && owner_op == OPERATION', True), ('! OPERATION [ 2 ]', True), ('dut.iteration == 32', True)],
     'dut.product == magnitude_product'),
    ('quotient_tracks_unprocessed_bits', 'assert', [('! reset && ! cancel && pending', True), ('dut.active && owner_op == OPERATION', True), ('! OPERATION [ 2 ]', False)],
     "( dut.quotient >> dut.iteration ) == ( owner_left_magnitude & ( 32'hffffffff >> dut.iteration ) )"),
    ('division_conservation', 'assert', [('! reset && ! cancel && pending', True), ('dut.active && owner_op == OPERATION', True), ('! OPERATION [ 2 ]', False)],
     "division_sum == { 33'd0 , dividend_prefix }"),
    ('remainder_fits_word', 'assert', [('! reset && ! cancel && pending', True), ('dut.active && owner_op == OPERATION', True), ('! OPERATION [ 2 ]', False)],
     '! dut.remainder [ 32 ]'),
    ('remainder_below_divisor', 'assert', [('! reset && ! cancel && pending', True), ('dut.active && owner_op == OPERATION', True), ('! OPERATION [ 2 ]', False), ('owner_right_magnitude != 0', True)],
     "dut.remainder < { 1'b0 , dut.divisor }"),
    ('division_terminal', 'assert', [('! reset && ! cancel && pending', True), ('dut.active && owner_op == OPERATION', True), ('! OPERATION [ 2 ]', False), ('dut.iteration == 32', True)],
     "{ 32'd0 , dut.remainder } + ( { 33'd0 , dut.divisor } * { 33'd0 , dut.quotient } ) == { 33'd0 , owner_left_magnitude }"),
    ('initial_synchronous_reset', 'assume', [('first_cycle', True)],
     'reset'),
    ('producer_keeps_valid', 'assume', [('reset', False), ('! cancel && history_valid && ! previous_reset && ! previous_cancel && previous_stall', True)],
     'request_valid'),
    ('producer_keeps_operation', 'assume', [('reset', False), ('! cancel && history_valid && ! previous_reset && ! previous_cancel && previous_stall', True)],
     'request_bits_operation == previous_operation'),
    ('producer_keeps_left', 'assume', [('reset', False), ('! cancel && history_valid && ! previous_reset && ! previous_cancel && previous_stall', True)],
     'request_bits_left == previous_left'),
    ('producer_keeps_right', 'assume', [('reset', False), ('! cancel && history_valid && ! previous_reset && ! previous_cancel && previous_stall', True)],
     'request_bits_right == previous_right'),
    ('cancel_suppresses_request', 'assert', [('reset', False), ('cancel', True)],
     '! request_ready'),
    ('cancel_suppresses_response', 'assert', [('reset', False), ('cancel', True)],
     '! response_valid'),
    ('occupied_unit_rejects_new_request', 'assert', [('reset', False), ('cancel', False), ('pending', True)],
     '! request_ready'),
    ('idle_unit_accepts_requests', 'assert', [('reset', False), ('cancel', False), ('pending', False)],
     'request_ready'),
    ('only_one_accepted_owner', 'assert', [('reset', False), ('cancel', False), ('accepted', True)],
     '! pending'),
    ('response_has_accepted_owner', 'assert', [('reset', False), ('cancel', False), ('response_valid', True)],
     'pending'),
    ('arithmetic_matches_reference', 'assert', [('reset', False), ('cancel', False), ('response_valid', True), ('owner_op == OPERATION', True)],
     'response_bits == expected'),
    ('result_deadline_age', 'assert', [('reset', False), ('cancel', False), ('pending && ! response_seen', True)],
     'age <= 34'),
    ('result_valid_by_34', 'assert', [('reset', False), ('cancel', False), ('pending && ! response_seen', True), ('age == 34', True)],
     'response_valid'),
    ('blocked_result_keeps_valid', 'assert', [('reset', False), ('cancel', False), ('history_valid && ! previous_reset && ! previous_cancel && previous_response_valid && ! previous_response_ready', True)],
     'response_valid'),
    ('blocked_result_keeps_value', 'assert', [('reset', False), ('cancel', False), ('history_valid && ! previous_reset && ! previous_cancel && previous_response_valid && ! previous_response_ready', True)],
     'response_bits == previous_response'),
    ('mixed_operation_completion', 'cover', [('reset', False)],
     'completed && owner_op == OPERATION && other_operation_completed'),
    ('request_reached', 'cover', [('reset', False)],
     'accepted && request_bits_operation == OPERATION'),
    ('high_operand_bits_reached', 'cover', [('reset', False)],
     'accepted && request_bits_operation == OPERATION && request_bits_left [ 31 ] && request_bits_right [ 31 ]'),
    ('zero_operand_reached', 'cover', [('reset', False)],
     'accepted && request_bits_operation == OPERATION && request_bits_right == 0'),
    ('result_reached', 'cover', [('reset', False)],
     'completed && owner_op == OPERATION'),
    ('cancellation_during_iteration_reached', 'cover', [('reset', False)],
     'pending && owner_op == OPERATION && cancel && age == 17 && ! response_seen'),
    ('cancellation_at_deadline_reached', 'cover', [('reset', False)],
     'pending && owner_op == OPERATION && cancel && age == 34 && ! response_seen'),
    ('blocked_result_cancellation_reached', 'cover', [('reset', False)],
     'pending && owner_op == OPERATION && cancel && response_seen && held_cycles >= 3'),
    ('held_result_completion_reached', 'cover', [('reset', False)],
     'completed && owner_op == OPERATION && held_cycles >= 3'),
    ('two_completions_reached', 'cover', [('reset', False)],
     'completed && owner_op == OPERATION && completed_once'),
    ('chain_variable_lsb_identity', 'assert', [],
     'chain_predicted_total == chain_total'),
    ('chain_owner_operation_stable', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_owner', True)],
     'owner_op == chain_previous_owner_operation'),
    ('chain_owner_left_stable', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_owner', True)],
     'owner_left == chain_previous_owner_left'),
    ('chain_owner_right_stable', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_owner', True)],
     'owner_right == chain_previous_owner_right'),
    ('chain_reference_stable', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_owner', True)],
     'magnitude_product == chain_previous_reference'),
    ('chain_expected_stable', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_owner', True)],
     'expected == chain_previous_expected'),
    ('chain_actual_step_active', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_step', True)],
     'dut.active && ! dut.valid'),
    ('chain_actual_step_iteration', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_step', True)],
     "dut.iteration == chain_previous_iteration + 6'd1"),
    ('chain_actual_step_product', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_step', True)],
     "dut.product == chain_previous_product + ( chain_previous_multiplier [ 0 ] ? chain_previous_multiplicand : 64'd0 )"),
    ('chain_actual_step_multiplicand', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_step', True)],
     "dut.multiplicand == { chain_previous_multiplicand [ 62 : 0 ] , 1'b0 }"),
    ('chain_actual_step_multiplier', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_step', True)],
     "dut.multiplier == { 1'b0 , chain_previous_multiplier [ 31 : 1 ] }"),
    ('chain_actual_total_update', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_step', True)],
     'chain_total == chain_previous_predicted_total'),
    ('chain_sampled_identity', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_step', True)],
     'chain_previous_predicted_total == chain_previous_total'),
    ('chain_total_preserved', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_step', True)],
     'chain_total == chain_previous_total'),
    ('chain_initial_state', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('dut.active && dut.iteration == 0', True)],
     "dut.product == 0 && dut.multiplicand == { 32'd0 , owner_left_magnitude } && dut.multiplier == owner_right_magnitude"),
    ('chain_initial_total', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('dut.active && dut.iteration == 0', True)],
     'chain_total == magnitude_product'),
    ('chain_terminal_multiplier_zero', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('dut.active && dut.iteration == 32', True)],
     'dut.multiplier == 0'),
    ('chain_terminal_total_is_product', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('dut.active && dut.iteration == 32', True)],
     'chain_total == dut.product'),
    ('chain_actual_finish_valid', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_finish', True)],
     'dut.valid && response_valid && ! dut.active'),
    ('chain_actual_finish_low', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_finish', True), ('OPERATION == 0', True)],
     'response_bits == chain_previous_product [ 31 : 0 ]'),
    ('chain_actual_finish_high', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_finish', True), ('OPERATION == 0', False)],
     'response_bits == chain_previous_corrected_product [ 63 : 32 ]'),
    ('chain_blocked_total_stable', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_hold', True)],
     'chain_total == chain_previous_total'),
    ('chain_owner_magnitudes_stable', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_owner', True)],
     'owner_left_magnitude == chain_previous_left_magnitude && owner_right_magnitude == chain_previous_right_magnitude'),
    ('chain_actual_hold_product', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_hold', True)],
     'dut.product == chain_previous_product'),
    ('chain_actual_hold_multiplicand', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_hold', True)],
     'dut.multiplicand == chain_previous_multiplicand'),
    ('chain_actual_hold_multiplier', 'assert', [('history_valid && ! reset && ! cancel && chain_selected_owner', True), ('chain_previous_mul_hold', True)],
     'dut.multiplier == chain_previous_multiplier'),
    ('epoch_active_has_predecessor', 'assert', [('! reset && ! cancel && chain_selected_owner && dut.active', True)],
     'history_valid && ( dut.iteration == 0 || ( chain_previous_mul_step && chain_previous_owner ) )'),
    ('snapshot_product_is_actual_past', 'assert', [('history_valid && ! reset && ! previous_reset', True)],
     'chain_previous_product == $past ( dut.product )'),
    ('snapshot_multiplicand_is_actual_past', 'assert', [('history_valid && ! reset && ! previous_reset', True)],
     'chain_previous_multiplicand == $past ( dut.multiplicand )'),
    ('snapshot_multiplier_is_actual_past', 'assert', [('history_valid && ! reset && ! previous_reset', True)],
     'chain_previous_multiplier == $past ( dut.multiplier )'),
    ('snapshot_owner_left_is_actual_past', 'assert', [('history_valid && ! reset && ! previous_reset', True)],
     'chain_previous_owner_left == $past ( owner_left )'),
    ('snapshot_owner_right_is_actual_past', 'assert', [('history_valid && ! reset && ! previous_reset', True)],
     'chain_previous_owner_right == $past ( owner_right )'),
    ('snapshot_owner_operation_is_actual_past', 'assert', [('history_valid && ! reset && ! previous_reset', True)],
     'chain_previous_owner_operation == $past ( owner_op )'),
    ('snapshot_mul_step_is_actual_past', 'assert', [('history_valid && ! reset', True)],
     'chain_previous_mul_step == ( ! previous_reset && $past ( ! cancel && chain_selected_owner && dut.active && dut.iteration < 32 ) )'),
    ('snapshot_owner_is_actual_past', 'assert', [('history_valid && ! reset', True)],
     'chain_previous_owner == ( ! previous_reset && $past ( ! cancel && chain_selected_owner ) )'),
    ('initial_frame_is_idle', 'assert', [('! reset && first_proof_frame', True)],
     '! pending && ! dut.active'),
    ('initial_frame_reached', 'cover', [],
     'first_proof_frame && ! reset'),
    ('captured_reference_matches_owner', 'assert', [('! reset && pending', True)],
     'expected == m_reference ( OPERATION , owner_left , owner_right )'),
    ('response_epoch_has_predecessor', 'assert', [('! reset && ! cancel && response_valid && owner_op == OPERATION', True)],
     'history_valid && pending && ( chain_previous_mul_finish || chain_previous_mul_hold )'),
    ('captured_reference_reached', 'cover', [],
     '! reset && pending && owner_op == OPERATION && owner_left [ 31 ] && owner_right [ 31 ]'),
    ('pending_capture_or_hold_predecessor', 'assert', [('! reset && pending', True)],
     'history_valid && ! previous_reset && ( $past ( accepted ) || $past ( pending ) )'),
    ('captured_expected_from_request', 'assert', [('history_valid && ! reset && ! previous_reset', True), ('$past ( accepted )', True)],
     'expected == $past ( m_reference ( OPERATION , request_bits_left , request_bits_right ) )'),
    ('captured_owner_left_from_request', 'assert', [('history_valid && ! reset && ! previous_reset', True), ('$past ( accepted )', True)],
     'owner_left == $past ( request_bits_left )'),
    ('captured_owner_right_from_request', 'assert', [('history_valid && ! reset && ! previous_reset', True), ('$past ( accepted )', True)],
     'owner_right == $past ( request_bits_right )'),
    ('expected_without_accept_holds', 'assert', [('history_valid && ! reset && ! previous_reset', True), ('$past ( accepted )', False)],
     'expected == $past ( expected )'),
    ('owner_left_without_accept_holds', 'assert', [('history_valid && ! reset && ! previous_reset', True), ('$past ( accepted )', False)],
     'owner_left == $past ( owner_left )'),
    ('owner_right_without_accept_holds', 'assert', [('history_valid && ! reset && ! previous_reset', True), ('$past ( accepted )', False)],
     'owner_right == $past ( owner_right )'),
    ('response_finish_has_actual_past_terminal_owner', 'assert', [('! reset && ! cancel && response_valid && owner_op == OPERATION', True), ('chain_previous_mul_finish', True)],
     'chain_previous_owner && $past ( ! reset && ! cancel && pending && dut.active && owner_op == OPERATION && dut.iteration == 32 )'),
    ('response_hold_has_actual_past_goal', 'assert', [('! reset && ! cancel && response_valid && owner_op == OPERATION', True), ('chain_previous_mul_hold', True)],
     '$past ( ! reset && ! cancel && response_valid && owner_op == OPERATION )'),
    ('response_hold_data_matches_past', 'assert', [('! reset && ! cancel && response_valid && owner_op == OPERATION', True), ('chain_previous_mul_hold', True)],
     'response_bits == $past ( response_bits )'),
    ('response_hold_expected_matches_past', 'assert', [('! reset && ! cancel && response_valid && owner_op == OPERATION', True), ('chain_previous_mul_hold', True)],
     'expected == $past ( expected )'),
    ('snapshot_negative_is_actual_past', 'assert', [('history_valid && ! reset && ! previous_reset', True)],
     'chain_previous_negative == $past ( dut.negative )'),
)

DEFINITIONS = {
    "chain_selected_owner": (1, "pending && owner_op == OPERATION && !OPERATION[2]"),
    "remaining_product": (64, "dut.multiplicand * {32'd0, dut.multiplier}"),
    "chain_total": (64, "dut.product + remaining_product"),
    "magnitude_product": (64, "{32'd0, owner_left_magnitude} * {32'd0, owner_right_magnitude}"),
    "chain_previous_total": (
        64,
        "chain_previous_product + chain_previous_multiplicand * {32'd0, chain_previous_multiplier}",
    ),
    "chain_previous_reference": (
        64,
        "{32'd0, chain_previous_left_magnitude} * {32'd0, chain_previous_right_magnitude}",
    ),
    "owner_left_signed": (1, "owner_op == 1 || owner_op == 2 || owner_op == 4 || owner_op == 6"),
    "owner_right_signed": (1, "owner_op == 1 || owner_op == 4 || owner_op == 6"),
    "owner_left_negative": (1, "owner_left_signed && owner_left[31]"),
    "owner_right_negative": (1, "owner_right_signed && owner_right[31]"),
    "owner_left_magnitude": (32, "owner_left_negative ? 32'd0 - owner_left : owner_left"),
    "owner_right_magnitude": (32, "owner_right_negative ? 32'd0 - owner_right : owner_right"),
    "chain_previous_left_signed": (
        1,
        "chain_previous_owner_operation == 1 || chain_previous_owner_operation == 2 || chain_previous_owner_operation == 4 || chain_previous_owner_operation == 6",
    ),
    "chain_previous_left_negative": (
        1,
        "chain_previous_left_signed && chain_previous_owner_left[31]",
    ),
    "chain_previous_left_magnitude": (
        32,
        "chain_previous_left_negative ? 32'd0 - chain_previous_owner_left : chain_previous_owner_left",
    ),
    "chain_previous_right_signed": (
        1,
        "chain_previous_owner_operation == 1 || chain_previous_owner_operation == 4 || chain_previous_owner_operation == 6",
    ),
    "chain_previous_right_negative": (
        1,
        "chain_previous_right_signed && chain_previous_owner_right[31]",
    ),
    "chain_previous_right_magnitude": (
        32,
        "chain_previous_right_negative ? 32'd0 - chain_previous_owner_right : chain_previous_owner_right",
    ),
    "chain_previous_predicted_product": (
        64,
        "chain_previous_product + (chain_previous_multiplier[0] ? chain_previous_multiplicand : 64'd0)",
    ),
    "chain_previous_predicted_multiplicand": (64, "{chain_previous_multiplicand[62:0], 1'b0}"),
    "chain_previous_predicted_multiplier": (32, "{1'b0, chain_previous_multiplier[31:1]}"),
    "chain_previous_predicted_total": (
        64,
        "chain_previous_predicted_product + chain_previous_predicted_multiplicand * {32'd0, chain_previous_predicted_multiplier}",
    ),
    "chain_previous_corrected_product": (
        64,
        "chain_previous_negative ? 64'd0 - chain_previous_product : chain_previous_product",
    ),
}


HELPER_TOKENS_SHA256 = "45292641b3848bd302f517270a5b4292373b34023fe306879ecf685e33ff62f2"
SCAFFOLD_SHA256 = "3e2c53b18552a2f5cbcaad18a8840a7dfb99876ee69d9eb403af389878d15086"


def scaffold(text, operation):
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    text = text.replace("parameter logic [2:0] OPERATION = 3'd" + str(operation),
                        "parameter logic [2:0] OPERATION = 3'd0")
    text = re.sub(r"\bfunction\b.*?\bendfunction\b", "", text, flags=re.S)
    values = syntax.tokens(text)
    kept = []
    position = 0
    while position < len(values):
        if values[position + 1:position + 3] in ([":", "assert"], [":", "assume"], [":", "cover"]):
            end = syntax.matching(values, position + 3)
            if values[end] != ";":
                raise ValueError("Malformed sampled property")
            position = end + 1
        else:
            kept.append(values[position])
            position += 1
    return kept


def structure(text, operation):
    values = scaffold(text, operation)
    digest = hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()
    if digest != SCAFFOLD_SHA256:
        raise ValueError("Multiplication ports, declarations, connections or drivers changed")
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    clean = re.sub(r"\bfunction\b.*?\bendfunction\b", "", clean, flags=re.S)
    ports = {name: {"direction": direction, "width": int(high) - int(low) + 1 if high else 1}
             for direction, high, low, name in re.findall(
                 r"\b(input|output)\s+logic\s+(?:\[(\d+):(\d+)\]\s+)?(\w+)", clean)}
    body = " ".join(values[values.index(";") + 1:])
    drivers = [{"signal": name, "operator": operator, "body": syntax.tokens(expression)}
               for name, operator, expression in re.findall(
                   r"\b([A-Za-z_$][\w$]*(?:\[[^\]]+\])?)\s*(<=|=(?!=))\s*([^;]+);", body)]
    declarations = []
    for kind, high, low, declaration in re.findall(
            r"\b(wire|logic|reg)\s+(?:\[(\d+):(\d+)\]\s+)?([^;]+);", body):
        declarations.append({"kind": kind, "width": int(high) - int(low) + 1 if high else 1,
                             "tokens": syntax.tokens(declaration)})
    return {"ports": ports, "declarations": declarations, "drivers": drivers,
            "scaffoldSha256": digest, "allNonPropertyTokensBound": True}


def dut_words(text):
    expected = {"product": 64, "multiplicand": 64, "multiplier": 32,
                "operation": 3, "iteration": 6, "negative": 1, "active": 1, "valid": 1}
    for name, width in expected.items():
        declarations = re.findall(r"\breg\s+(?:\[(\d+):(\d+)\]\s+)?" + name + r"\s*;", text)
        if len(declarations) != 1:
            raise ValueError("DUT arithmetic word declaration differs: " + name)
        high, low = declarations[0]
        if (int(high) - int(low) + 1 if high else 1) != width:
            raise ValueError("DUT arithmetic word width differs: " + name)
    return expected


def bind(operation, text, dut_text=None, helper_text=None):
    if operation not in range(4):
        raise ValueError("Multiplication operation is invalid")
    parameter = "parameter logic [2:0] OPERATION = 3'd" + str(operation)
    if text.count(parameter) != 1:
        raise ValueError("Multiplication parameter differs from the native configuration")
    if len(re.findall(r"\bassume\s*\(", text)) != 5:
        raise ValueError("Multiplication environment assumptions differ")
    parsed = syntax.properties(text)
    if set(parsed) != {row[0] for row in CONTRACTS}:
        raise ValueError("Multiplication property inventory changed")
    source.reference(text)
    checked_structure = structure(text, operation)
    helper_text = helper_text if helper_text is not None else (source.HERE / "multiply_step.sv").read_text()
    helper_hash = hashlib.sha256(json.dumps(syntax.tokens(helper_text), separators=(",", ":")).encode()).hexdigest()
    if helper_hash != HELPER_TOKENS_SHA256:
        raise ValueError("Multiplication polynomial helper changed")
    checked = {}
    for label, kind, guards, body in CONTRACTS:
        expected = {
            "kind": kind,
            "clock": syntax.tokens("posedge clock"),
            "body": syntax.tokens(body),
            "guards": [
                {"tokens": syntax.tokens(guard), "positive": polarity} for guard, polarity in guards
            ],
        }
        if parsed.get(label) != expected:
            raise ValueError("Multiplication source contract differs: " + label)
        checked[label] = expected
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    drivers = re.findall(r"\bprevious_reset\s*(<=|=(?!=))\s*([^;]+);", clean)
    if drivers != [("<=", "reset")]:
        raise ValueError("Previous reset must sample the actual clock")
    first = re.findall(r"\bfirst_proof_frame\s*(<=|=(?!=))\s*([^;]+);", clean)
    if first != [("=", "1'b1"), ("<=", "1'b1"), ("<=", "1'b0")]:
        raise ValueError("First frame observer changed")
    definitions = {}
    for name, (width, expression) in DEFINITIONS.items():
        matches = re.findall(r"\bwire\s+(?:\[(\d+):(\d+)\]\s+)?" + name + r"\s*=([^;]+);", clean)
        if len(matches) != 1:
            raise ValueError("Missing typed multiplication definition: " + name)
        high, low, body = matches[0]
        actual_width = int(high) - int(low) + 1 if high else 1
        if actual_width != width or syntax.tokens(body) != syntax.tokens(expression):
            raise ValueError("Multiplication substitution differs: " + name)
        definitions[name] = {"width": width, "expression": expression}
    return {
        "operation": operation,
        "structure": checked_structure,
        "polynomialHelperTokensSha256": helper_hash,
        "dutStateWidths": dut_words(dut_text) if dut_text is not None else None,
        "contracts": checked,
        "definitions": definitions,
        "sourceSha256": source.digest(text.encode()),
        "guard": "!reset && !cancel && response_valid && owner_op == OPERATION",
        "operandBitsEach": 32,
        "actualOperationBits": 3,
        "referenceFunctionSha256": source.REFERENCE_HASH,
    }
