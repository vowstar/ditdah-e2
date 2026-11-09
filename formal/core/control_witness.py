# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Require the named interface error in a formal counterexample."""


def frames(content, wanted):
    scopes, identifiers, values = [], {}, {}
    stamp = 0
    for line in content.splitlines():
        fields = line.split()
        if fields[:1] == ["$scope"]:
            scopes.append(fields[2])
        elif fields[:1] == ["$upscope"]:
            scopes.pop()
        elif fields[:1] == ["$var"] and len(scopes) == 1 and fields[4] in wanted:
            identifiers[fields[3]] = fields[4]
        elif line.startswith("#"):
            if values:
                yield stamp, values.copy()
            stamp = int(line[1:])
        elif line.startswith("b") and len(fields) == 2 and fields[1] in identifiers:
            bits = fields[0][1:]
            values[identifiers[fields[1]]] = int(bits, 2) if set(bits) <= {"0", "1"} else None
        elif line[:1] in ("0", "1", "x", "z") and line[1:] in identifiers:
            values[identifiers[line[1:]]] = int(line[0]) if line[0] in "01" else None
    assert set(identifiers.values()) == wanted, "Counterexample observations missing"
    yield stamp, values.copy()


def witness(content, name):
    if name == "address-increment":
        wanted = {"reset", "clock", "request", "redirect", "pause", "canceled_offer", "stream_valid",
                  "memory_request_valid", "memory_request_bits_address", "expected_request"}
    elif name == "stale-response":
        wanted = {"reset", "clock", "redirect", "outstanding", "response", "poisoned", "flush", "available",
                  "output_valid", "output_bits_pc", "output_bits_word", "expected_pc", "expected_word"}
    else:
        assert name == "source-priority", "Unknown control witness"
        wanted = {"reset", "clock", "interrupt_valid", "interrupt_cause", "pending_sources", "irq_active"}
    samples = list(frames(content, wanted))
    prior_request = redirected = stale_response = False
    for stamp, row in samples:
        if any(row.get(key) is None for key in wanted) or row["clock"] != 1:
            continue
        if row["reset"]:
            prior_request = redirected = stale_response = False
            continue
        if name == "address-increment":
            if row["redirect"] or row["pause"]:
                prior_request = False
            if (prior_request and row["memory_request_valid"] and row["stream_valid"]
                    and not row["canceled_offer"] and row["memory_request_bits_address"] != row["expected_request"]):
                return {"time": stamp, **row}
            prior_request |= bool(row["request"] and not row["redirect"] and not row["pause"])
        elif name == "stale-response":
            redirected |= bool(row["redirect"] and row["outstanding"])
            stale_response |= bool(redirected and row["response"] and row["poisoned"])
            wrong_output = (not row["available"] or row["output_bits_pc"] != row["expected_pc"]
                            or row["output_bits_word"] != row["expected_word"])
            if stale_response and row["output_valid"] and not row["flush"] and wrong_output:
                return {"time": stamp, "redirectedOutstanding": True, "staleResponseAccepted": True, **row}
        elif row["irq_active"] and row["interrupt_valid"] and row["pending_sources"].bit_count() > 1:
            mask = row["pending_sources"]
            expected = 0x8000000B if mask & 4 else 0x80000003 if mask & 1 else 0x80000007
            if row["interrupt_cause"] != expected:
                return {"time": stamp, "expectedCause": expected, **row}
    raise AssertionError("Missing intended semantic counterexample")
