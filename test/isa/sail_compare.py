# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Compare DUT packets with native Sail observations, without executing an ISA model."""

from sail_operands import is_hint, sources

class ComparisonError(ValueError):
    """A covered architectural observation differs."""


STATES = {0x300: "mstatus", 0x341: "mepc", 0x342: "mcause", 0x343: "mtval"}


def _require(condition, message):
    if not condition:
        raise ComparisonError(message)


def _sources(step, parameters):
    if step.instruction is None:
        return 0, 0
    return sources(step.instruction, step.length, parameters)


def _memory(record, step):
    _require(record["memory_operation"] == 0, "Atomic instructions require the actual endpoint witness path")
    effects = [effect for effect in step.memory if effect.kind != "X"]
    _require(len(effects) <= 1, "Ordinary fixture contains multiple data effects")
    if step.trap:
        _require(not effects, "Faulting Sail instruction exposed a successful data effect")
    expected_read = expected_write = 0
    if effects:
        effect, = effects
        lane = effect.address & 3
        _require(lane + effect.width <= 4, "A data effect crosses an aligned native word")
        mask = ((1 << effect.width) - 1) << lane
        _require(record["mem_addr"] == effect.address & ~3, "Data address differs")
        bits = ((1 << (8 * effect.width)) - 1) << (8 * lane)
        field = "mem_wdata" if effect.write else "mem_rdata"
        _require(record[field] & bits == effect.value << (8 * lane), "Data bytes differ")
        if effect.write:
            expected_write = mask
        else:
            expected_read = mask
    _require(record["mem_rmask"] == expected_read, "Memory read mask differs")
    _require(record["mem_wmask"] == expected_write, "Memory write mask differs")
    _require(record["mem_fault"] == (step.trap and step.cause in (1, 5, 7)), "Memory fault classification differs")
    fault_read = fault_write = 0
    if step.trap and step.cause in (5, 7):
        opcode = step.instruction & 0x7f
        width = 1 << (step.instruction >> 12 & 3)
        _require(step.length == 4 and opcode in (0x03, 0x23) and width <= 4,
                 "Unsupported faulting data instruction")
        lane = step.tval & 3
        _require(lane + width <= 4 and record["mem_addr"] == step.tval & ~3, "Faulting data address differs")
        mask = ((1 << width) - 1) << lane
        fault_write = mask if opcode == 0x23 else 0
        fault_read = mask if opcode == 0x03 else 0
    if step.trap and step.cause == 1:
        _require(record["mem_addr"] == 0, "Fetch fault contains a data address")
        _require(all(record[field] == 0 for field in ("mem_rdata", "mem_wdata", "memory_operand", "memory_response")),
                 "Fetch fault contains data transaction values")
    _require(record["mem_fault_rmask"] == fault_read and record["mem_fault_wmask"] == fault_write,
             "Attempted fault lanes differ")


def compare_signature(actual, expected):
    """Require the complete independently observed signature, including its extent."""
    _require(actual == expected, "Actual RTL memory signature differs from Sail")


def compare(records, steps, parameters, *, checked_end, completion_pc, tohost, memory_checker=None):
    """Compare the fixed body and validate the complete HTIF/completion suffix."""
    _require(not parameters["enableDebug"] and (not parameters["enableA"] or memory_checker is not None),
             "Unsupported independent environment")
    _require(bool(steps) and len(records) > len(steps), "Missing native execution or DUT completion suffix")
    _require(steps[0].pc == parameters["resetVector"], "Native entry differs")
    end = [index for index, step in enumerate(steps) if step.pc == checked_end]
    _require(len(end) == 1, "Missing or repeated checked body boundary")
    _require(len(steps) - end[0] == 6, "Unexpected HTIF teardown instruction count")
    _require(steps[-1].memory[-1].write and steps[-1].memory[-1].address == tohost + 4
             and steps[-1].memory[-1].width == 4 and steps[-1].memory[-1].value == 0,
             "Native execution did not complete the high half of its HTIF command")
    _require(steps[-2].memory[-1].write and steps[-2].memory[-1].address == tohost
             and steps[-2].memory[-1].width == 4 and steps[-2].memory[-1].value == 1,
             "Native HTIF success payload is missing")
    for index, record in enumerate(records):
        _require(record["order"] == index, "DUT order is not consecutive")
        if index:
            _require(records[index - 1]["cycle"] < record["cycle"], "DUT cycles are not increasing")
            _require(records[index - 1]["pc_wdata"] == record["pc_rdata"], "DUT adjacent PCs are discontinuous")
    for index in range(len(steps), len(records)):
        record, previous = records[index], records[index - 1]
        _require(not record["trap"] and record["pc_rdata"] == record["pc_wdata"] == completion_pc
                 and record["insn"] == 0x0000006f and record["rd_addr"] == 0
                 and record["mem_rmask"] == record["mem_wmask"] == 0 and not record["csr"]["valid"],
                 "DUT suffix is not a side-effect-free completion loop")
        _require(not record["intr"] and not record["halt"] and record["length"] == 4
                 and record["mode"] == previous["mode"] and record["misa"] == previous["misa"]
                 and all(record[field] == 0 for field in ("rs1_addr", "rs2_addr", "rs1_rdata", "rs2_rdata", "rd_wdata",
                         "mem_addr", "mem_rdata", "mem_wdata", "mem_fault_rmask", "mem_fault_wmask", "memory_operation",
                         "memory_operand", "memory_response")) and not record["mem_fault"]
                 and record["csr"]["rmask"] == record["csr"]["wmask"] == 0,
                 "DUT completion loop has inactive operand, memory or CSR metadata")
        for name, state in record["csr_states"].items():
            _require(state["wmask"] == 0 and state["after"] == state["before"], "DUT completion loop changes CSR state")
            if name in STATES.values():
                _require(state["before"] == previous["csr_states"][name]["after"], "DUT completion CSR state is discontinuous")
    misa = {access.value for step in steps for access in step.csrs if access.address == 0x301 and not access.write}
    _require(len(misa) == 1, "The native fixed-MISA observation is missing or inconsistent")
    misa, = misa
    registers = {0: 0}
    states, counter_halves = {}, {}
    inhibit = None
    pending_handler = False
    state_comparisons = counter_comparisons = csr_reads = live_minstret_reads = hint_normalizations = 0
    for index, (record, step) in enumerate(zip(records, steps)):
        label = f" at native step {index}"
        def equal(field, value):
            _require(record[field] == value, field + " differs" + label)
        equal("order", index)
        equal("pc_rdata", step.pc)
        equal("insn", step.instruction if step.instruction is not None else 0)
        if step.length is not None:
            equal("length", step.length)
        equal("mode", step.mode)
        equal("misa", misa)
        equal("trap", step.trap)
        equal("intr", pending_handler)
        pending_handler = step.trap
        if index + 1 < len(steps):
            equal("pc_wdata", steps[index + 1].pc)
        if step.trap:
            equal("cause", step.cause)
            equal("tval", step.tval)
        writes = [(register, value) for register, value in step.register_writes if register]
        if step.instruction is not None and is_hint(step.instruction, step.length, parameters):
            _require(all(register in registers and registers[register] == value for register, value in writes)
                     and not any(effect.kind != "X" for effect in step.memory) and not step.csrs,
                     "A native compressed HINT has an observable effect" + label)
            raw = step.instruction
            destination = 8 + (raw >> 7 & 7) if raw & 3 == 1 and raw >> 13 == 4 else raw >> 7 & 31
            if destination and not writes:
                _require(destination in registers, "The HINT identity value is not independently known" + label)
                writes = [(destination, registers[destination])]
                hint_normalizations += 1
        equal("rd_addr", writes[0][0] if writes else 0)
        equal("rd_wdata", writes[0][1] if writes else 0)
        first, second = _sources(step, parameters)
        for slot, source in ((1, first), (2, second)):
            _require(source in registers, "Native source value was not independently initialized" + label)
            equal(f"rs{slot}_addr", source)
            equal(f"rs{slot}_rdata", registers[source])
        if memory_checker is not None and record["memory_operation"]:
            memory_checker(record, step)
        else:
            _memory(record, step)
        access = record["csr"]
        is_csr = step.length == 4 and step.instruction & 0x7f == 0x73 and (step.instruction >> 12 & 7) in (1, 2, 3, 5, 6, 7)
        _require(access["valid"] == (is_csr and not step.trap), "Legal CSR access classification differs" + label)
        if access["valid"]:
            address = step.instruction >> 20
            _require(access["address"] == address, "Dynamic CSR address differs" + label)
            function = step.instruction >> 12 & 7
            read = not (function in (1, 5) and step.instruction >> 7 & 31 == 0)
            _require(access["rmask"] == (0xffffffff if read else 0), "CSR read suppression differs" + label)
            native_reads = [item.value for item in step.csrs if item.address == address and not item.write]
            if read:
                if not native_reads and writes and writes[0][0] == step.instruction >> 7 & 31:
                    native_reads = [writes[0][1]]
                _require(len(native_reads) == 1 and access["rdata"] == native_reads[0], "Native CSR read differs" + label)
                csr_reads += 1
            if address in (0xc01, 0xc81):
                raise ComparisonError("External time requires an explicit matched input protocol")
            if address in (0xb00, 0xb80, 0xc00, 0xc80):
                _require(inhibit is not None and inhibit & 1, "A free-running cycle read is not comparable to ISS steps")
            if read and address in (0xb02, 0xb82, 0xc02, 0xc82) and inhibit is not None and not inhibit & 4:
                live_minstret_reads += 1
        before = dict(states)
        for low, name, bit in ((0xb00, "mcycle", 0), (0xb02, "minstret", 2)):
            if inhibit is not None and inhibit & (1 << bit) and low in counter_halves and low + 0x80 in counter_halves:
                expected = counter_halves[low] | counter_halves[low + 0x80] << 32
                _require(record["csr_states"][name]["before"] == expected, name + " inhibited pre-state differs" + label)
                counter_comparisons += 1
        for item in step.csrs:
            if not item.write and item.address in STATES and item.address not in before:
                before[item.address] = item.value
            if item.write and item.address in STATES:
                states[item.address] = item.value
            if item.write and item.address == 0x320:
                inhibit = item.value
            if item.address in (0xb00, 0xb80, 0xb02, 0xb82):
                counter_halves[item.address] = item.value
        for address, name in STATES.items():
            actual = record["csr_states"][name]
            if address in before:
                _require(actual["before"] == before[address], name + " pre-state differs" + label)
                state_comparisons += 1
            if address not in states and address in before:
                states[address] = before[address]
            if address in states:
                _require(actual["after"] == states[address], name + " post-state differs" + label)
                state_comparisons += 1
        for low, name, bit in ((0xb00, "mcycle", 0), (0xb02, "minstret", 2)):
            if inhibit is not None and inhibit & (1 << bit) and low in counter_halves and low + 0x80 in counter_halves:
                expected = counter_halves[low] | counter_halves[low + 0x80] << 32
                _require(record["csr_states"][name]["after"] == expected, name + " inhibited state differs" + label)
                counter_comparisons += 1
            elif inhibit is None or not inhibit & (1 << bit):
                counter_halves.pop(low, None)
                counter_halves.pop(low + 0x80, None)
        registers.update(writes)
    return {"nativeEventsCompared": len(steps), "bodyBoundaryIndex": end[0],
            "completionLoopPackets": len(records) - len(steps), "nativeMisa": misa,
            "csrReadsCompared": csr_reads, "implicitCsrValuesCompared": state_comparisons,
            "inhibitedCounterValuesCompared": counter_comparisons,
            "unobservedTerminalNextPc": 1, "csrWriteMasksExternallyCompared": False,
            "unavailableFetchFaultInstructionLengths": sum(step.length is None for step in steps),
            "liveMinstretCompared": live_minstret_reads > 0,
            "liveMinstretReadsCompared": live_minstret_reads, "externalTimeCompared": False,
            "unloggedHintIdentityWrites": hint_normalizations,
            "atomicEndpointCompared": bool(parameters["enableA"] and memory_checker is not None),
            "debugOrInterruptScheduleCompared": False}
