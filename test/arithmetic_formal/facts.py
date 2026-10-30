# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Native facts used by the independent arithmetic proof."""

INSTRUCTIONS = ("mul", "mulh", "mulhsu", "mulhu")
ASSUMPTIONS = ("initial_synchronous_reset", "producer_keeps_valid", "producer_keeps_operation", "producer_keeps_left", "producer_keeps_right")

MULTIPLY = (('blocked_result_keeps_value', ()),
 ('blocked_result_keeps_valid', ()),
 ('result_valid_by_34', ()),
 ('result_deadline_age', ()),
 ('response_has_accepted_owner', ()),
 ('only_one_accepted_owner', ()),
 ('idle_unit_accepts_requests', ()),
 ('occupied_unit_rejects_new_request', ()),
 ('cancel_suppresses_response', ()),
 ('cancel_suppresses_request', ()),
 ('polynomial_lsb0.exact_polynomial_transition', ()),
 ('polynomial_lsb1.exact_polynomial_transition', ()),
 ('chain_variable_lsb_identity',
  ('polynomial_lsb0.exact_polynomial_transition',
   'polynomial_lsb1.exact_polynomial_transition')),
 ('chain_actual_step_active', ()),
 ('chain_actual_step_iteration', ()),
 ('chain_actual_step_product', ()),
 ('chain_actual_step_multiplicand', ()),
 ('chain_actual_step_multiplier', ()),
 ('chain_sampled_identity', ('chain_variable_lsb_identity',)),
 ('chain_owner_operation_stable', ()),
 ('chain_owner_left_stable', ()),
 ('chain_owner_right_stable', ()),
 ('chain_expected_stable', ()),
 ('owner_has_actual_state', ()),
 ('owner_operation', ()),
 ('owner_sign', ()),
 ('owner_remainder_sign', ()),
 ('owner_zero_divisor', ()),
 ('owner_raw_dividend', ()),
 ('owner_divisor', ()),
 ('iteration_in_range', ()),
 ('multiplier_tracks_remaining_bits', ()),
 ('multiplicand_tracks_iteration', ()),
 ('chain_initial_state', ()),
 ('chain_terminal_multiplier_zero', ('multiplier_tracks_remaining_bits',)),
 ('chain_terminal_total_is_product', ('chain_terminal_multiplier_zero',)),
 ('chain_actual_finish_valid', ()),
 ('chain_actual_finish_low', ()),
 ('chain_owner_magnitudes_stable',
  ('chain_owner_operation_stable',
   'chain_owner_left_stable',
   'chain_owner_right_stable')),
 ('chain_actual_hold_product', ()),
 ('chain_actual_hold_multiplicand', ()),
 ('chain_actual_hold_multiplier', ()),
 ('epoch_active_has_predecessor', ()),
 ('snapshot_product_is_actual_past', ()),
 ('snapshot_multiplicand_is_actual_past', ()),
 ('snapshot_multiplier_is_actual_past', ()),
 ('snapshot_owner_left_is_actual_past', ()),
 ('snapshot_owner_right_is_actual_past', ()),
 ('snapshot_owner_operation_is_actual_past', ()),
 ('snapshot_mul_step_is_actual_past', ()),
 ('snapshot_owner_is_actual_past', ()),
 ('initial_frame_is_idle', ()),
 ('pending_capture_or_hold_predecessor', ()),
 ('captured_expected_from_request', ()),
 ('captured_owner_left_from_request', ()),
 ('captured_owner_right_from_request', ()),
 ('expected_without_accept_holds', ()),
 ('owner_left_without_accept_holds', ()),
 ('owner_right_without_accept_holds', ()),
 ('response_epoch_has_predecessor', ()),
 ('response_finish_has_actual_past_terminal_owner', ()),
 ('response_hold_has_actual_past_goal', ()),
 ('response_hold_data_matches_past', ()),
 ('response_hold_expected_matches_past', ()),
 ('snapshot_negative_is_actual_past', ()))


def goals(operation):
    if type(operation) is not int or not 0 <= operation < 4:
        raise ValueError("Unknown arithmetic operation")
    values = MULTIPLY
    if operation in (1, 2, 3):
        values = tuple((name.replace("finish_low", "finish_high"),
                        tuple(dep.replace("finish_low", "finish_high") for dep in deps))
                       for name, deps in values)
    established = set()
    for name, dependencies in values:
        if name in established or set(dependencies) - established:
            raise ValueError("Native fact graph has a missing or cyclic dependency")
        established.add(name)
    return values


def covers(operation):
    initial = "initial_frame_reached"
    return (initial, "result_reached", "held_result_completion_reached",
            "high_operand_bits_reached", "mixed_operation_completion")
