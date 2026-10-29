# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Join checked shared-memory history to actual SRAM and retirement samples."""

from collections import defaultdict

from retirement import AtomicWitness, TraceError, bind_native_trace, require, unsigned, validate_record


PORTS = ("instruction", "data", "debug", "competitor")
HISTORY_KEYS = {"acceptedCycle", "memoryCycle", "port", "request", "oldValue", "writeValue",
                "response", "reservationBefore", "reservationAfter"}


def _integers(fields, label):
    try:
        return list(map(int, fields))
    except ValueError as error:
        raise TraceError(label + ": malformed integer") from error


def _port(sample, index):
    start = 1 + index * 13
    return sample[start:start + 13]


def _samples(stdout):
    samples, clocks, transactions = {}, [], []
    pending = None
    total = None
    for line, text in enumerate(stdout.splitlines(), 1):
        fields = text.split()
        require(fields and total is None, f"atomic line {line}: empty or post-completion record")
        kind = fields[0]
        require(kind in ("T", "B", "C", "P", "Q", "S", "R", "N", "A", "V", "J", "K", "L", "H", "F"),
                f"atomic line {line}: unknown record")
        require(kind not in ("N", "J", "K", "L", "H"), "atomic retirement join does not support IRQ/debug boundaries")
        if kind == "F":
            require(len(fields) == 2, "Malformed atomic completion")
            total = _integers(fields[1:], "completion")[0]
            continue
        require(len(fields) >= 2, "Missing atomic event cycle")
        cycle = _integers(fields[1:2], "cycle")[0]
        unsigned(cycle, 64, "cycle")
        if kind == "T":
            row = _integers(fields[1:], "clock")
            require(len(row) == 8 and cycle == len(clocks), "Missing atomic clock sample")
            unsigned(row[1], 64, "time")
            require(all(value in (0, 1) for value in row[2:]), "Malformed atomic clock flag")
            require(not (row[2] or row[4] or row[7]),
                    "atomic retirement join does not support reset/debug/IRQ boundaries")
            clocks.append(row)
        else:
            require(clocks and cycle == len(clocks) - 1, "Atomic event lacks its clock")
        if kind == "B":
            row = _integers(fields[2:], "SRAM sample")
            require(len(row) == 57 and cycle not in samples, "Missing or duplicate SRAM cycle sample")
            require(row[0] == clocks[-1][3], "Reservation-clear sample differs from clock")
            unsigned(row[0], 1, "clear")
            for index in range(4):
                port = _port(row, index)
                for value, width in zip(port, (1, 32, 1, 1, 32, 4, 2, 4, 1, 1, 1, 32, 1), strict=True):
                    unsigned(value, width, "SRAM port sample")
                require(port[10] or port[11:] == [0, 0], "Inactive SRAM response carries data")
            for value, width in zip(row[-4:], (1, 32, 4, 32), strict=True):
                unsigned(value, width, "SRAM writer sample")
            require(row[-2] or row[-1] == 0, "Inactive SRAM writer carries data")
            samples[cycle] = row
        if kind in ("Q", "S") and len(fields) >= 3 and fields[2] == "D":
            values = _integers(fields[3:], "native data transaction")
            if kind == "Q":
                require(pending is None and len(values) == 7, "Overlapping or malformed native data owner")
                pending = {"accepted": cycle, "request": tuple(values)}
            else:
                require(pending is not None and len(values) == 2 and cycle > pending["accepted"],
                        "Native data response lacks an owner")
                transactions.append(pending | {"responded": cycle, "response": tuple(values)})
                pending = None
    require(total == len(clocks) and total > 0 and len(samples) == total and pending is None,
            "Incomplete atomic clock/SRAM/native trace")
    return samples, transactions


def join_atomic_witnesses(records, stdout, shared_history, *, sram_base, sram_size):
    """Return successful atomic witnesses; require the existing full SRAM check first.

    History supplies ownership and expected observations. Actual writer values
    come exclusively from B samples, never from operand arithmetic or writeValue.
    Lifecycle and interrupt boundaries are rejected until their join is defined.
    """
    unsigned(sram_base, 32, "SRAM base")
    require(type(sram_size) is int and sram_size >= 4 and sram_size % 4 == 0 and
            sram_base % 4 == 0 and sram_base + sram_size <= 1 << 32, "Invalid SRAM region")
    records = list(records)
    for record in records:
        validate_record(record)
    samples, native = _samples(stdout)
    bind_native_trace(records, stdout)
    histories = list(shared_history)
    accepted, committed, by_port = {}, {}, defaultdict(list)
    for history in histories:
        require(type(history) is dict and set(history) == HISTORY_KEYS, "Malformed shared history")
        port = history["port"]
        require(port in PORTS and port != "debug", "Unsupported shared-history owner")
        start, commit = history["acceptedCycle"], history["memoryCycle"]
        unsigned(start, 64, "history.acceptedCycle")
        unsigned(commit, 64, "history.memoryCycle")
        require(start < commit and start in samples and commit in samples, "History lacks actual endpoint cycles")
        require(start not in accepted and commit not in committed, "Ambiguous shared-memory owner")
        request, response = history["request"], history["response"]
        require(type(request) in (list, tuple) and len(request) == 7 and
                type(response) in (list, tuple) and len(response) == 2, "Malformed shared-history payload")
        for value, width in zip(request, (32, 1, 1, 32, 4, 2, 4), strict=True):
            unsigned(value, width, "history.request")
        for value, width in zip(response, (32, 1), strict=True):
            unsigned(value, width, "history.response")
        for field in ("oldValue", "writeValue", "reservationBefore", "reservationAfter"):
            if history[field] is not None:
                unsigned(history[field], 32, "history." + field)
        require(not request[-1] or port == "data", "Atomic endpoint operation has a different owner")
        actual = _port(samples[start], PORTS.index(port))
        require(actual[0] == actual[9] == 1 and tuple(actual[1:8]) == tuple(request),
                "History request differs from actual accepted endpoint request")
        legal = not response[1]
        require(samples[start][-4] == int(legal), "History lacks its actual SRAM read")
        if legal:
            require(sram_base <= request[0] < sram_base + sram_size and
                    sram_base + samples[start][-3] * 4 == request[0] & ~3,
                    "Actual SRAM read address differs from its owner")
        mask, data = samples[commit][-2:]
        expected_mask = request[4] if history["writeValue"] is not None else 0
        require(mask == expected_mask and (mask == 0 or data == history["writeValue"]),
                "Actual SRAM writer differs from checked history")
        if mask:
            require(sram_base + samples[commit][-3] * 4 == request[0] & ~3,
                    "Actual SRAM write address differs from its owner")
        accepted[start], committed[commit] = history, history
        by_port[port].append(history)
    # Bind every accepted owner and every physical write, including competitors.
    actual_starts = {(cycle, PORTS[index]) for cycle, row in samples.items() for index in range(4)
                     if (port := _port(row, index))[0] and port[9]}
    require(actual_starts == {(start, history["port"]) for start, history in accepted.items()},
            "Extra or missing endpoint acceptance outside shared history")
    require(all(not row[-2] or cycle in committed for cycle, row in samples.items()),
            "Physical write lacks a shared-history owner")
    endpoint_responses = {}
    for index, port in enumerate(PORTS):
        responses = [(cycle, tuple(value[11:13])) for cycle, row in samples.items()
                     if (value := _port(row, index))[10] and value[8]]
        ordered = sorted(by_port[port], key=lambda history: history["acceptedCycle"])
        require(len(responses) == len(ordered), "Endpoint response count differs from shared history")
        for (cycle, response), history in zip(responses, ordered, strict=True):
            require(cycle > history["memoryCycle"] and response == tuple(history["response"]),
                    "Endpoint response differs from checked owner/result")
            endpoint_responses[history["acceptedCycle"]] = cycle, response
    native_by_cycle = {transaction["responded"]: transaction for transaction in native}
    require(len(native_by_cycle) == len(native), "Ambiguous native response cycle")
    native_starts = {transaction["accepted"] for transaction in native}
    require(all(history["port"] != "data" or start in native_starts for start, history in accepted.items()),
            "Data history lacks an accepted native owner")
    for transaction in native:
        address, write, data, mask, size, machine, operation = transaction["request"]
        if sram_base <= address < sram_base + sram_size:
            start = transaction["accepted"]
            require(start in accepted and accepted[start]["port"] == "data", "Native SRAM request lost data ownership")
            require(tuple(accepted[start]["request"]) == (address, machine, write, data, mask, size, operation),
                    "Native request differs from accepted SRAM payload")
            require(endpoint_responses[start] == (transaction["responded"], transaction["response"]),
                    "Native response differs from actual endpoint response")
    results, used = [], set()
    for record in records:
        operation = record["memory_operation"]
        if operation == 0:
            continue
        transaction = native_by_cycle.get(record["cycle"])
        if record["trap"] and transaction is None:
            require(record["cause"] in (4, 5, 6, 7) and record["memory_response"] == 0,
                    "Unsupported atomic trap without a native response")
            continue
        require(transaction is not None and transaction["request"][-1] == operation,
                "Atomic retirement lacks its actual native response")
        start = transaction["accepted"]
        address, _, data, _, _, _, _ = transaction["request"]
        require(address == record["mem_addr"] and data == record["memory_operand"] and
                transaction["response"][0] == record["memory_response"], "Core/endpoint atomic payload differs")
        used.add(record["cycle"])
        if record["trap"]:
            require(transaction["response"][1] == 1, "Trapping atomic native response was successful")
            continue
        require(start in accepted and accepted[start]["port"] == "data" and transaction["response"][1] == 0,
                "Successful atomic lacks an actual SRAM owner")
        history = accepted[start]
        commit = history["memoryCycle"]
        actual_mask, actual_data = samples[commit][-2:]
        old = endpoint_responses[start][1][0] if operation != 2 else 0
        results.append(AtomicWitness(record["order"], address, operation, data, old,
                                     actual_mask, actual_data, start, commit, transaction["responded"]))
    require(all(not transaction["request"][-1] or transaction["responded"] in used for transaction in native),
            "Extra native atomic transaction lacks a retirement owner")
    return results
