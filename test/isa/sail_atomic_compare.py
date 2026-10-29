# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Compare real SRAM effects with native Sail atomic memory callbacks."""

import copy

from sail_atomic_samples import sample_atomic_witnesses
from sail_compare import ComparisonError, compare, compare_signature


OPERATIONS = {2: 1, 3: 2, 1: 3, 0: 4, 4: 5, 12: 6, 8: 7, 16: 8, 20: 9, 24: 10, 28: 11}


def memory_checker(samples):
    witnesses = {item["order"]: item for item in samples["witnesses"]}
    unissued = {item["order"]: item for item in samples["unissuedFaults"]}
    if len(witnesses) != len(samples["witnesses"]) or len(unissued) != len(samples["unissuedFaults"]) or witnesses.keys() & unissued.keys():
        raise ComparisonError("Repeated atomic endpoint owner")
    def check(record, step):
        def require(condition, text):
            if not condition:
                raise ComparisonError(text + f" at atomic order {record['order']}")
        operation = OPERATIONS.get(step.instruction >> 27)
        require(step.length == 4 and step.instruction & 0x7f == 0x2f and operation == record["memory_operation"],
                "Atomic operation differs")
        require(record["memory_operand"] == (0 if operation == 1 else record["rs2_rdata"]), "Atomic operand differs")
        effects = [item for item in step.memory if item.kind != "X"]
        reads = [item for item in effects if not item.write]
        writes = [item for item in effects if item.write]
        require(len(reads) <= 1 and len(writes) <= 1, "Repeated native atomic effect")
        actual = witnesses.get(record["order"])
        if step.trap:
            require(not effects and record["mem_rmask"] == record["mem_wmask"] == 0, "Faulting atomic has a successful effect")
            require(record["mem_addr"] == step.tval & ~3, "Atomic fault address differs")
            require(record["mem_fault"] == (step.cause in (5, 7)), "Atomic fault classification differs")
            access = step.cause in (5, 7)
            require(record["mem_fault_rmask"] == (15 if access and operation != 2 else 0) and
                    record["mem_fault_wmask"] == (15 if access and operation != 1 else 0), "Atomic attempted lanes differ")
            if actual is None:
                require(record["order"] in unissued and record["memory_response"] == 0, "Atomic fault has no endpoint disposition")
            else:
                require(actual["response_fault"] and actual["writer"]["mask"] == 0, "Faulting atomic wrote SRAM")
            return
        require(actual is not None and not actual["response_fault"], "Successful atomic lacks an actual SRAM response")
        require(not record["mem_fault"] and record["mem_fault_rmask"] == record["mem_fault_wmask"] == 0,
                "Successful atomic contains fault metadata")
        require(all(item.width == 4 and item.address == record["mem_addr"] for item in effects), "Atomic address or width differs")
        if operation == 2:
            require(not reads, "Native SC exposed a load result")
            status = 0 if writes else 1
            require(record["memory_response"] == status == actual["response_data"], "SC status differs")
        else:
            require(len(reads) == 1 and record["mem_rdata"] == reads[0].value == actual["response_data"] == record["memory_response"],
                    "Atomic old word differs")
            require(bool(writes) == (operation >= 3), "Atomic effect type differs")
        require(record["mem_rmask"] == (0 if operation == 2 else 15), "Atomic read lanes differ")
        require(record["mem_wmask"] == (15 if operation == 2 and writes else 0), "Atomic retirement write lanes differ")
        require(record["mem_wdata"] == (0 if operation == 1 else record["memory_operand"]), "Atomic request write data differs")
        writer = actual["writer"]
        require(writer["mask"] == (15 if writes else 0), "Actual SRAM write lanes differ from Sail")
        if writes:
            require(writer["address"] == writes[0].address and writer["data"] == writes[0].value,
                    "Actual SRAM write bytes differ from Sail")
    return check


def signature_from_samples(samples, begin, end):
    reads = samples["competitorReads"]
    if len(reads) != (end - begin) // 4 or [item["address"] for item in reads] != list(range(begin, end, 4)) or any(item["fault"] for item in reads):
        raise ComparisonError("Actual SRAM signature reads are incomplete, reordered or faulting")
    return [item["data"] for item in reads]


def corruption_controls(records, steps, parameters, samples, boundaries, stdout, begin, end, expected, *, sram_base, sram_size):
    controls = []
    for description in ("actual AMO writer", "failed SC physical store"):
        changed = copy.deepcopy(samples)
        if description == "actual AMO writer":
            writer = next(row for row in changed["witnesses"] if row["operation"] >= 3)["writer"]
            writer["data"] ^= 1
        else:
            writer = next(row for row in changed["witnesses"] if row["operation"] == 2 and row["response_data"] == 1)["writer"]
            writer["mask"] = 15
        try:
            compare(records, steps, parameters, **(boundaries | {"memory_checker": memory_checker(changed)}))
        except ComparisonError as error:
            controls.append({"mutation": description, "rejection": str(error)})
        else:
            raise ComparisonError("Changed actual atomic effect was accepted")
    first = samples["competitorReads"][0]
    changed_lines = []
    for line in stdout.splitlines():
        fields = line.split()
        if fields[0] == "V" and int(fields[1]) == first["cycle"]:
            fields[3] = str(int(fields[3]) ^ 1)
        if fields[0] == "B" and first["request_cycle"] < int(fields[1]) <= first["cycle"]:
            # B has cycle followed by clear and four thirteen-field ports.
            # Flip the complete held competitor response with its V sample.
            if int(fields[52]):
                fields[53] = str(int(fields[53]) ^ 1)
        changed_lines.append(" ".join(fields))
    changed = sample_atomic_witnesses(records, "\n".join(changed_lines) + "\n", sram_base=sram_base, sram_size=sram_size)
    try:
        compare_signature(signature_from_samples(changed, begin, end), expected)
    except ComparisonError as error:
        controls.append({"mutation": "actual signature read", "rejection": str(error)})
    else:
        raise ComparisonError("Changed actual SRAM signature was accepted")
    return controls
