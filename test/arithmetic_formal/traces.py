# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Replay actual request ownership and standard integer results from traces."""

import hashlib

TOP = "md_math_bench."


def architectural_result(operation, left, right):
    mask = (1 << 32) - 1
    signed = lambda value: value - (1 << 32) if value & 1 << 31 else value
    if operation == 0:
        return left * right & mask
    if operation in (1, 2, 3):
        first = signed(left) if operation in (1, 2) else left
        second = signed(right) if operation == 1 else right
        return (first * second & (1 << 64) - 1) >> 32
    if operation not in (4, 5, 6, 7):
        raise ValueError("Arithmetic operation is invalid")
    first = signed(left) if operation in (4, 6) else left
    second = signed(right) if operation in (4, 6) else right
    if second == 0:
        return mask if operation in (4, 5) else left
    quotient = abs(first) // abs(second)
    if (first < 0) != (second < 0):
        quotient = -quotient
    return (quotient if operation in (4, 5) else first - quotient * second) & mask


def frames(path, signals):
    scopes = []
    ids = {}
    values = {}
    rows = []
    time = 0
    for line in path.read_text().splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "$scope":
            scopes.append(parts[2])
        elif parts[0] == "$upscope":
            scopes.pop()
        elif parts[0] == "$var":
            name = ".".join(scopes + [parts[4]])
            for key, (signal, width) in signals.items():
                if name == signal:
                    if not int(parts[2]) == width:
                        raise ValueError("Trace contract failed")
                    ids[key] = parts[3]
        elif line.startswith("#"):
            if values:
                rows.append((time, dict(values)))
            time = int(line[1:])
        elif line[0] in "01xXzZ":
            values[line[1:].strip()] = line[0].lower()
        elif line[0] in "bB":
            value, code = line[1:].split()
            values[code] = value.lower()
    if values:
        rows.append((time, dict(values)))
    if not set(ids) == set(signals):
        raise ValueError("Trace contract failed")
    result = []
    for time, row in rows:
        decoded = {}
        for key, code in ids.items():
            value = row.get(code)
            if not (value is not None and set(value) <= {"0", "1"}):
                raise ValueError("Trace contract failed")
            decoded[key] = int(value, 2)
        result.append({"time": time, **decoded})
    samples = [
        row
        for i, row in enumerate(result)
        if row["clock"] == 1 and (i == 0 or result[i - 1]["clock"] == 0)
    ]
    if not samples:
        raise ValueError("Trace contract failed")
    return samples


def replay_result(path, operation):
    if operation not in range(8):
        raise ValueError("Arithmetic operation is invalid")
    widths = {
        "clock": 1,
        "reset": 1,
        "cancel": 1,
        "request_valid": 1,
        "request_ready": 1,
        "request_bits_operation": 3,
        "request_bits_left": 32,
        "request_bits_right": 32,
        "response_valid": 1,
        "response_ready": 1,
        "response_bits": 32,
        "expected": 32,
        "accepted": 1,
        "owner_op": 3,
    }
    signals = {name: (TOP + name, width) for name, width in widths.items()}
    samples = frames(path, signals)
    owner = None
    accepted = []
    hits = []
    for i, row in enumerate(samples):
        offered = (
            not row["reset"]
            and (not row["cancel"])
            and row["request_valid"]
            and row["request_ready"]
        )
        if not row["accepted"] == int(offered):
            raise ValueError("Trace contract failed")
        if row["reset"] or row["cancel"]:
            owner = None
            continue
        if i:
            previous = samples[i - 1]
            if (
                not previous["reset"]
                and (not previous["cancel"])
                and previous["request_valid"]
                and (not previous["request_ready"])
            ):
                if not (
                    row["request_valid"]
                    and all(
                        (
                            row[key] == previous[key]
                            for key in [
                                "request_bits_operation",
                                "request_bits_left",
                                "request_bits_right",
                            ]
                        )
                    )
                ):
                    raise ValueError("Trace contract failed")
            if (
                not previous["reset"]
                and (not previous["cancel"])
                and previous["response_valid"]
                and (not previous["response_ready"])
            ):
                if not (
                    row["response_valid"] and row["response_bits"] == previous["response_bits"]
                ):
                    raise ValueError("Trace contract failed")
        if row["response_valid"]:
            if not (owner is not None and row["owner_op"] == owner["operation"]):
                raise ValueError("Trace contract failed")
            if row["owner_op"] == operation:
                standard = architectural_result(operation, owner["left"], owner["right"])
                if not row["response_bits"] == row["expected"] == standard:
                    raise ValueError("Trace contract failed")
                if not row["response_bits"] != row["expected"] ^ 1:
                    raise ValueError("Trace contract failed")
                hits.append(
                    {
                        "sample": i,
                        "time": row["time"],
                        "acceptedOwner": dict(owner),
                        "standardResult": standard,
                        "originalGuardSatisfied": True,
                        "originalComparisonTrue": True,
                        "bitMutationFalse": True,
                    }
                )
            if row["response_ready"]:
                owner = None
        if offered:
            if not owner is None:
                raise ValueError("Trace contract failed")
            owner = {
                "operation": row["request_bits_operation"],
                "left": row["request_bits_left"],
                "right": row["request_bits_right"],
                "acceptedSample": i,
                "acceptedTime": row["time"],
            }
            accepted.append(dict(owner))
    if not hits:
        raise ValueError("Trace contract failed")
    return {
        "operation": operation,
        "samples": len(samples),
        "acceptedRequests": accepted,
        "effectiveGoalBitCounterexample": True,
        "ownerDerivedFromActualRequestHandshake": True,
        "originalResultMatchesIndependentIntegerModel": True,
        "hits": hits,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def replay_cover(path, operation, label):
    widths = {"clock": 1, "reset": 1}
    first_frame = (
        "division_first_proof_frame"
        if label == "division_initial_frame_reached"
        else "first_proof_frame"
    )
    if label.endswith("initial_frame_reached"):
        widths[first_frame] = 1
    elif label == "high_operand_bits_reached":
        widths.update(
            accepted=1, request_bits_operation=3, request_bits_left=32, request_bits_right=32
        )
    else:
        widths.update(completed=1, owner_op=3)
        if label == "held_result_completion_reached":
            widths["held_cycles"] = 3
        elif label == "mixed_operation_completion":
            widths["other_operation_completed"] = 1
        elif label != "result_reached":
            raise ValueError("Unknown arithmetic cover")
    samples = frames(path, {name: (TOP + name, width) for name, width in widths.items()})
    hits = []
    for index, row in enumerate(samples):
        if row["reset"]:
            continue
        if label.endswith("initial_frame_reached"):
            reached = row[first_frame]
        elif label == "high_operand_bits_reached":
            reached = (
                row["accepted"]
                and row["request_bits_operation"] == operation
                and row["request_bits_left"] & (1 << 31)
                and row["request_bits_right"] & (1 << 31)
            )
        else:
            reached = row["completed"] and row["owner_op"] == operation
            if label == "held_result_completion_reached":
                reached = reached and row["held_cycles"] >= 3
            if label == "mixed_operation_completion":
                reached = reached and row["other_operation_completed"]
        if reached:
            hits.append(index)
    if not hits:
        raise ValueError("The cover trace does not satisfy its actual predicate")
    return {
        "replayed": True,
        "samples": len(samples),
        "hits": hits,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
