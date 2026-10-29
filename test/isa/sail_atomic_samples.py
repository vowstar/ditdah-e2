# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Extract actual atomic endpoint effects without an ISA or reservation model."""

from retirement import bind_native_trace, validate_record


PORTS = ("instruction", "data", "debug", "competitor")
REQUEST_FIELDS = ("address", "machine", "write", "data", "mask", "size", "operation")
PORT_WIDTHS = (1, 32, 1, 1, 32, 4, 2, 4, 1, 1, 1, 32, 1)


class SampleError(ValueError):
    """An observation has no unambiguous actual transaction owner."""


def _require(condition, message):
    if not condition:
        raise SampleError(message)


def _unsigned(value, width, label):
    _require(type(value) is int and 0 <= value < 1 << width, "Invalid unsigned " + label)


def _numbers(fields):
    try:
        return list(map(int, fields))
    except ValueError as error:
        raise SampleError("Malformed sample integer") from error


def _port(row, index):
    return row[1 + 13 * index:14 + 13 * index]


def _parse(stdout):
    clocks, samples, native, signatures = [], [], [], []
    pending = None
    total = None
    for text in stdout.splitlines():
        fields = text.split()
        _require(fields and total is None, "Empty or post-completion atomic record")
        kind = fields[0]
        _require(kind in ("T", "B", "C", "P", "Q", "S", "R", "A", "V", "F", "N", "H", "J", "K", "L"),
                 "Unknown atomic record")
        _require(kind not in ("N", "H", "J", "K", "L"), "Unsupported IRQ/debug boundary")
        if kind == "F":
            _require(len(fields) == 2, "Malformed atomic completion")
            total = _numbers(fields[1:])[0]
            continue
        _require(len(fields) >= 2, "Missing atomic sample cycle")
        cycle = _numbers(fields[1:2])[0]
        _unsigned(cycle, 64, "cycle")
        if kind == "T":
            row = _numbers(fields[1:])
            _require(len(row) == 8 and cycle == len(clocks), "Missing atomic clock")
            _unsigned(row[1], 64, "time")
            _require(all(value in (0, 1) for value in row[2:]), "Invalid clock control flag")
            _require(not (row[2] or row[4] or row[7]), "Unsupported reset/debug/IRQ boundary")
            clocks.append(row)
        else:
            _require(clocks and cycle == len(clocks) - 1, "Atomic record lacks its clock")
        if kind == "B":
            row = _numbers(fields[2:])
            _require(cycle == len(samples) and len(row) == 57, "Missing or duplicate endpoint sample")
            _require(row[0] == clocks[-1][3], "Reservation-clear observation differs")
            _unsigned(row[0], 1, "clear")
            for index in range(4):
                port = _port(row, index)
                for value, width in zip(port, PORT_WIDTHS, strict=True):
                    _unsigned(value, width, "endpoint field")
                _require(port[10] or port[11:] == [0, 0], "Inactive response carries a payload")
            for value, width in zip(row[-4:], (1, 32, 4, 32), strict=True):
                _unsigned(value, width, "SRAM field")
            _require(row[-2] or row[-1] == 0, "Inactive writer carries data")
            samples.append(row)
        if kind in ("Q", "S") and len(fields) >= 3 and fields[2] == "D":
            values = _numbers(fields[3:])
            if kind == "Q":
                _require(pending is None and len(values) == 7, "Overlapping or malformed core data request")
                address, write, data, mask, size, machine, operation = values
                pending = {"request_cycle": cycle,
                           "request": dict(zip(REQUEST_FIELDS, (address, machine, write, data, mask, size, operation)))}
            else:
                _require(pending is not None and len(values) == 2 and cycle > pending["request_cycle"],
                         "Unowned core data response")
                native.append(pending | {"response_cycle": cycle, "response_data": values[0], "response_fault": values[1]})
                pending = None
        if kind == "V":
            values = _numbers(fields[1:])
            _require(len(values) == 4, "Malformed competitor signature result")
            for value, width in zip(values, (64, 32, 32, 1), strict=True):
                _unsigned(value, width, "signature field")
            signatures.append(dict(zip(("cycle", "address", "data", "fault"), values)))
    _require(total == len(clocks) == len(samples) and total > 0 and pending is None,
             "Incomplete atomic clock, endpoint or core transaction stream")
    return samples, native, signatures


def _endpoint_transactions(samples, base, size):
    # Only transaction staging is reconstructed: acceptance, one execution
    # slot, and the response register. No result or reservation is predicted.
    executing = None
    responses = [None] * 4
    held_requests = [None] * 4
    complete = []
    for cycle, row in enumerate(samples):
        ports = [_port(row, index) for index in range(4)]
        _require(not ports[2][0], "Unsupported debug endpoint request")
        for index, port in enumerate(ports):
            valid, payload = port[0], tuple(port[1:8])
            if held_requests[index] is not None:
                _require(valid and payload == held_requests[index], "Held endpoint request changed")
            held_requests[index] = payload if valid and not port[9] else None
            owner = responses[index]
            if owner is None:
                _require(not port[10], "Endpoint response has no executed owner")
            else:
                _require(port[10], "Executed endpoint owner lost its response")
                pair = port[11], port[12]
                if "response_data" in owner:
                    _require(pair == (owner["response_data"], owner["response_fault"]), "Held response changed")
                owner.update(response_data=pair[0], response_fault=pair[1])
                _require(pair[1] or owner["read_cycle"] is not None, "Successful endpoint response lacks an actual read")
                _require(not pair[1] or owner["writer"]["mask"] == 0, "Faulting endpoint response has a physical write")
                if port[8]:
                    owner["response_cycle"] = cycle
                    complete.append(owner)
                    responses[index] = None
        accepted = [index for index, port in enumerate(ports) if port[0] and port[9]]
        _require(len(accepted) <= 1, "Multiple endpoint owners accepted in one cycle")
        read, word_address, mask, data = row[-4:]
        if executing is not None:
            _require(cycle == executing["request_cycle"] + 1 and not accepted and not read,
                     "Endpoint execution slot overlaps another acceptance/read")
            request = executing["request"]
            _require(not mask or request["write"] and mask & ~request["mask"] == 0,
                     "Physical writer is not owned by its accepted request")
            address = base + 4 * word_address if mask else None
            if mask:
                _require(address == request["address"] & ~3 and base <= address < base + size,
                         "Actual writer address differs from its owner")
            executing.update(execution_cycle=cycle, writer={"cycle": cycle if mask else None,
                              "address": address, "mask": mask, "data": data})
            index = PORTS.index(executing["port"])
            _require(responses[index] is None, "Endpoint execution overwrites a response owner")
            responses[index], executing = executing, None
        else:
            _require(mask == 0, "Physical write has no execution owner")
            if accepted:
                index = accepted[0]
                _require(responses[index] is None, "Endpoint accepted into an occupied response slot")
                request = dict(zip(REQUEST_FIELDS, ports[index][1:8]))
                _require(not request["operation"] or index == 1, "Atomic operation has a different endpoint owner")
                address = base + word_address * 4 if read else None
                if read:
                    _require(address == request["address"] & ~3 and base <= address < base + size,
                             "Actual read address differs from its owner")
                executing = {"port": PORTS[index], "request_cycle": cycle, "request": request,
                             "read_cycle": cycle if read else None, "read_address": address}
            else:
                _require(not read, "Physical read has no accepted owner")
    _require(executing is None and not any(responses) and not any(held_requests), "Endpoint owners did not drain")
    return complete


def sample_atomic_witnesses(records, stdout, *, sram_base, sram_size):
    """Return serializable actual effects and signature reads, with no ISA oracle.

    A zero write mask means no physical write; its cycle/address are None.
    execution_cycle names the current controller's accept-plus-one slot, not a
    fabricated write. Debug, IRQ and warm-reset lifecycles are unsupported.
    """
    _unsigned(sram_base, 32, "SRAM base")
    _require(type(sram_size) is int and sram_size >= 4 and sram_size % 4 == 0 and
             sram_base % 4 == 0 and sram_base + sram_size <= 1 << 32, "Invalid SRAM region")
    records = list(records)
    previous_cycle = -1
    for order, record in enumerate(records):
        validate_record(record)
        _require(record["order"] == order and record["cycle"] > previous_cycle,
                 "Nonconsecutive retirement order or cycle")
        previous_cycle = record["cycle"]
    samples, native, signatures = _parse(stdout)
    bind_native_trace(records, stdout)
    endpoint = _endpoint_transactions(samples, sram_base, sram_size)
    by_start = {event["request_cycle"]: event for event in endpoint if event["port"] == "data"}
    _require(len(by_start) == sum(event["port"] == "data" for event in endpoint), "Ambiguous data endpoint owner")
    native_starts = {event["request_cycle"] for event in native}
    _require(all(start in native_starts for start in by_start), "Data endpoint lacks its core request")
    for event in native:
        address = event["request"]["address"]
        if sram_base <= address < sram_base + sram_size:
            actual = by_start.get(event["request_cycle"])
            _require(actual is not None and actual["request"] == event["request"] and
                     all(actual[key] == event[key] for key in ("response_cycle", "response_data", "response_fault")),
                     "Core and actual SRAM transaction differ")
    by_response = {event["response_cycle"]: event for event in native}
    _require(len(by_response) == len(native), "Ambiguous core response owner")
    witnesses, unissued, used = [], [], set()
    for record in records:
        operation = record["memory_operation"]
        if not operation:
            continue
        event = by_response.get(record["cycle"])
        if record["trap"] and event is None:
            _require(record["cause"] in (4, 5, 6, 7) and record["memory_response"] == 0 and
                     record["mem_rmask"] == record["mem_wmask"] == 0 and
                     not any(item["request_cycle"] <= record["cycle"] < item["response_cycle"] for item in native),
                     "Atomic trap crossed an unfinished core transaction")
            unissued.append({"order": record["order"], "cycle": record["cycle"], "operation": operation,
                             "cause": record["cause"]})
            continue
        _require(event is not None and event["request"]["operation"] == operation and
                 event["request"]["address"] == record["mem_addr"] and
                 event["request"]["data"] == record["memory_operand"] and
                 event["response_data"] == record["memory_response"], "Atomic packet lacks its actual native operation")
        used.add(record["cycle"])
        if record["trap"]:
            _require(event["response_fault"] == 1, "Atomic trap has a successful actual response")
        else:
            _require(event["response_fault"] == 0, "Successful atomic packet has a faulting response")
        actual = by_start.get(event["request_cycle"])
        _require(actual is not None, "Atomic operation has no actual shared-SRAM samples")
        witnesses.append({"order": record["order"], "cycle": record["cycle"], "operation": operation, **actual})
    _require(all(not event["request"]["operation"] or event["response_cycle"] in used for event in native),
             "Extra native atomic operation lacks a retirement")
    competitors = {(event["response_cycle"], event["request"]["address"]): event
                   for event in endpoint if event["port"] == "competitor"}
    reads, seen = [], set()
    for result in signatures:
        key = result["cycle"], result["address"]
        actual = competitors.get(key)
        _require(key not in seen and actual is not None and actual["request"]["write"] == 0 and
                 actual["request"]["operation"] == 0 and actual["request"]["size"] == 2 and
                 (actual["response_data"], actual["response_fault"]) == (result["data"], result["fault"]),
                 "Signature result lacks its actual competitor read")
        reads.append(result | {"request_cycle": actual["request_cycle"]})
        seen.add(key)
    return {"schema": "ditdah-e2.sail-atomic-samples.v1", "witnesses": witnesses,
            "competitorReads": reads, "unissuedFaults": unissued}
