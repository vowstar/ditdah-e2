# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Validate observed retirement records; this is not a Sail event oracle."""

import argparse
from collections import Counter
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys


SCHEMA = "ditdah-e2.rvfi.v1"
INTERRUPT_SCHEMA = "ditdah-e2.irq.v1"
MASK = (1 << 32) - 1
WIDTHS = {
    "cycle": 64, "order": 64, "insn": 32, "mode": 2, "ixl": 2,
    "rs1_addr": 5, "rs2_addr": 5, "rs1_rdata": 32, "rs2_rdata": 32,
    "rd_addr": 5, "rd_wdata": 32, "pc_rdata": 32, "pc_wdata": 32,
    "mem_addr": 32, "mem_rmask": 4, "mem_wmask": 4,
    "mem_rdata": 32, "mem_wdata": 32, "mem_fault_rmask": 4,
    "mem_fault_wmask": 4, "length": 3, "cause": 32, "tval": 32,
    "misa": 32, "memory_operation": 4, "memory_operand": 32,
    "memory_response": 32, "time": 64,
}
FLAGS = {"trap", "halt", "intr", "mem_fault"}
CSR_WIDTHS = {"address": 12, "rmask": 32, "wmask": 32, "rdata": 32, "wdata": 32}
STATE_WIDTHS = {"mstatus": 32, "mepc": 32, "mcause": 32,
                "mtval": 32, "mcycle": 64, "minstret": 64}
ATOMIC_OPERATIONS = {2: 1, 3: 2, 1: 3, 0: 4, 4: 5, 12: 6,
                     8: 7, 16: 8, 20: 9, 24: 10, 28: 11}


class TraceError(ValueError):
    """A record or its observed sequence violates the trace contract."""


def require(condition, message):
    if not condition:
        raise TraceError(message)


def unsigned(value, width, label):
    require(type(value) is int and 0 <= value < 1 << width,
            f"{label}: expected unsigned {width}-bit integer")


def members(value, keys, label):
    require(type(value) is dict, f"{label}: expected object")
    missing, extra = set(keys) - value.keys(), value.keys() - set(keys)
    require(not missing, f"{label}: missing fields {sorted(missing)}")
    require(not extra, f"{label}: unknown fields {sorted(extra)}")


def _states(value, widths, label):
    members(value, widths, label)
    for name, width in widths.items():
        state = value[name]
        members(state, {"before", "after", "wmask"}, f"{label}.{name}")
        for key, number in state.items():
            unsigned(number, width, f"{label}.{name}.{key}")
        require((state["before"] ^ state["after"]) & ~state["wmask"] == 0,
                f"{label}: {name} changed outside its write mask")


def validate_record(record, label="record"):
    """Check exact keys, scalar types, widths and context-free invariants."""
    members(record, set(WIDTHS) | FLAGS | {"schema", "csr", "csr_states"}, label)
    require(record["schema"] == SCHEMA, f"{label}: unsupported schema")
    for name, width in WIDTHS.items():
        unsigned(record[name], width, f"{label}.{name}")
    for name in FLAGS:
        require(type(record[name]) is bool, f"{label}.{name}: expected Boolean")
    require(record["mode"] in (0, 3), f"{label}: unsupported privilege mode")
    require(record["ixl"] == 1, f"{label}: expected RV32 ixl")
    require(not record["halt"], f"{label}: permanent halt is not implemented")
    require(record["length"] in (2, 4), f"{label}: invalid instruction length")
    require(record["memory_operation"] <= 11, f"{label}: unknown memory operation")
    require(record["mem_addr"] % 4 == 0, f"{label}: memory address is not word aligned")
    alignment = 2 if record["misa"] & 4 else 4
    require(record["pc_rdata"] % alignment == 0, f"{label}: misaligned instruction PC")
    require(record["pc_wdata"] % alignment == 0, f"{label}: misaligned next PC")
    for source in ("rs1", "rs2"):
        require(record[source + "_addr"] != 0 or record[source + "_rdata"] == 0,
                f"{label}: {source} x0 data is nonzero")
    require(record["rd_addr"] != 0 or record["rd_wdata"] == 0,
            f"{label}: rd x0 data is nonzero")
    csr = record["csr"]
    members(csr, {"valid"} | set(CSR_WIDTHS), label + ".csr")
    require(type(csr["valid"]) is bool, f"{label}.csr.valid: expected Boolean")
    for name, width in CSR_WIDTHS.items():
        unsigned(csr[name], width, f"{label}.csr.{name}")
    require(csr["valid"] or csr["rmask"] == csr["wmask"] == 0,
            f"{label}: inactive CSR has an access mask")
    _states(record["csr_states"], STATE_WIDTHS, label + ".csr_states")
    if record["trap"]:
        require(record["rd_addr"] == record["rd_wdata"] == 0,
                f"{label}: trapping instruction writes a GPR")
        require(not csr["valid"], f"{label}: trapping instruction has an explicit CSR effect")
        require(record["mem_rmask"] == record["mem_wmask"] == 0,
                f"{label}: trapping instruction has successful memory masks")
    if record["mem_fault"]:
        require(record["trap"] and record["cause"] in (1, 5, 7),
                f"{label}: memory fault has no matching access trap")
    if record["trap"] and record["cause"] in (1, 5, 7):
        require(record["mem_fault"], f"{label}: access trap lacks memory fault")
    if not record["mem_fault"] or record["cause"] == 1:
        require(record["mem_fault_rmask"] == record["mem_fault_wmask"] == 0,
                f"{label}: fault masks without a data access fault")
    if record["trap"] and record["cause"] == 1:
        require(record["insn"] == record["mem_addr"] == 0,
                f"{label}: fetch fault contains an instruction or data address")
    elif record["length"] == 2:
        require(record["misa"] & 4 and record["insn"] < 1 << 16 and record["insn"] & 3 != 3,
                f"{label}: invalid raw compressed instruction")
    else:
        require(not record["misa"] & 4 or record["insn"] & 3 == 3,
                f"{label}: instruction length differs from its raw encoding")
    return record


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member {key}")
        result[key] = value
    return result


def parse_jsonl(text):
    """Parse only complete retirement objects; reject unknown record kinds."""
    require(type(text) is str, "trace input must be text")
    records = []
    for line, value in enumerate(text.splitlines(), 1):
        require(value.strip(), f"line {line}: empty record")
        try:
            row = json.loads(value, object_pairs_hook=_unique_object,
                             parse_constant=lambda value: (_ for _ in ()).throw(TraceError("nonfinite JSON number")))
            records.append(validate_record(row, f"line {line}"))
        except (json.JSONDecodeError, TraceError) as error:
            raise TraceError(f"line {line}: {error}") from error
    require(records, "trace has no retirement records")
    return records


def read_trace(path):
    return parse_jsonl(Path(path).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Interrupt:
    cycle: int
    pc: int
    target: int
    cause: int
    mode: int | None = None
    csr_states: dict | None = None


def parse_interrupt_jsonl(text):
    """Read actual IRQ transitions from their independent JSONL sidecar."""
    require(type(text) is str, "interrupt trace input must be text")
    result = []
    for line, value in enumerate(text.splitlines(), 1):
        label = f"interrupt line {line}"
        require(value.strip(), f"{label}: empty record")
        try:
            row = json.loads(value, object_pairs_hook=_unique_object,
                             parse_constant=lambda value: (_ for _ in ()).throw(TraceError("nonfinite JSON number")))
            members(row, {"schema", "cycle", "pc", "target", "cause", "mode", "csr_states"}, label)
            require(row["schema"] == INTERRUPT_SCHEMA, f"{label}: unsupported schema")
            for name, width in (("cycle", 64), ("pc", 32), ("target", 32), ("cause", 32), ("mode", 2)):
                unsigned(row[name], width, label + "." + name)
            require(row["mode"] in (0, 3), f"{label}: unsupported privilege mode")
            _states(row["csr_states"], {name: 32 for name in ("mstatus", "mepc", "mcause", "mtval")}, label)
            result.append(Interrupt(row["cycle"], row["pc"], row["target"], row["cause"], row["mode"], row["csr_states"]))
        except (json.JSONDecodeError, TraceError) as error:
            raise TraceError(f"{label}: {error}") from error
    return result


def read_interrupts(path):
    return parse_interrupt_jsonl(Path(path).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Boundary:
    cycle: int
    kind: str
    pc: int | None = None
    registers: dict = field(default_factory=dict)
    mode: int | None = None


@dataclass(frozen=True)
class AtomicWitness:
    """Actual endpoint samples joined to an instruction by its observer."""

    order: int
    address: int
    operation: int
    operand: int
    old_data: int
    write_mask: int
    write_data: int
    request_cycle: int
    commit_cycle: int
    response_cycle: int
    owner: str = "data"
    epoch: int = 0


def interrupts_from_stdout(text):
    result = []
    for line, value in enumerate(text.splitlines(), 1):
        fields = value.split()
        if not fields or fields[0] != "N":
            continue
        require(len(fields) == 5, f"stdout line {line}: malformed interrupt")
        try:
            result.append(Interrupt(*map(int, fields[1:])))
        except ValueError as error:
            raise TraceError(f"stdout line {line}: malformed interrupt integer") from error
    return result


def bind_native_trace(records, stdout, interrupts=()):
    """Bind JSON observations to the unchanged native R/N observation stream."""
    records, interrupts = list(records), list(interrupts)
    native = []
    for line, text in enumerate(stdout.splitlines(), 1):
        fields = text.split()
        if not fields or fields[0] != "R":
            continue
        require(len(fields) == 12, f"stdout line {line}: malformed retirement")
        try:
            values = tuple(map(int, fields[1:]))
        except ValueError as error:
            raise TraceError(f"stdout line {line}: malformed retirement integer") from error
        cycle, pc, word, next_pc, rd, writes, value, trap, cause, tval, user = values
        require(writes in (0, 1) and trap in (0, 1) and user in (0, 1),
                f"stdout line {line}: invalid retirement flags")
        native.append({"cycle": cycle, "pc_rdata": pc,
                       "insn": 0 if trap and cause == 1 else word,
                       "pc_wdata": next_pc, "rd_addr": rd if writes else 0,
                       "rd_wdata": value if writes else 0, "trap": bool(trap),
                       "mode": 0 if user else 3, **({"cause": cause, "tval": tval} if trap else {})})
    require(len(records) == len(native), "JSON/native retirement count differs")
    for index, (record, observed) in enumerate(zip(records, native)):
        validate_record(record, f"packet {index}")
        require(all(record[key] == value for key, value in observed.items()),
                f"packet {index}: JSON/native retirement observation differs")
    native_interrupts = interrupts_from_stdout(stdout)
    require(len(interrupts) == len(native_interrupts), "JSON/native interrupt count differs")
    for index, (record, observed) in enumerate(zip(interrupts, native_interrupts)):
        require(isinstance(record, Interrupt) and
                (record.cycle, record.pc, record.target, record.cause) ==
                (observed.cycle, observed.pc, observed.target, observed.cause),
                f"interrupt {index}: JSON/native interrupt observation differs")
    return {"retirement_records": len(native), "interrupt_records": len(native_interrupts)}


def _signed(value, width=32):
    return (value & ((1 << (width - 1)) - 1)) - (value & (1 << (width - 1)))


def _decoded(record):
    from compressed_model import decode
    decoded = decode(record["insn"], enable_c=bool(record["misa"] & 4))
    return decoded.expanded if decoded.legal else None


def _sources(word):
    opcode, function = word & 127, (word >> 12) & 7
    left, right = (word >> 15) & 31, (word >> 20) & 31
    use_left = opcode in (0x03, 0x13, 0x23, 0x2F, 0x33, 0x63, 0x67) or \
        opcode == 0x73 and function in (1, 2, 3)
    use_right = opcode in (0x23, 0x33, 0x63) or opcode == 0x2F and word >> 27 != 2
    if opcode == 0x33 and word >> 25 == 4 and function == 4 and right == 0:
        use_right = False
    return left if use_left else 0, right if use_right else 0


def _integer_result(word, left, right, pc, length):
    from bit_model import execute
    from model import multiply_divide
    opcode, function, upper = word & 127, (word >> 12) & 7, word >> 25
    bit = execute(word, left, right, True, True, True)
    if bit is not None:
        return bit[1]
    if opcode == 0x37:
        return word & 0xFFFFF000
    if opcode == 0x17:
        return (pc + (word & 0xFFFFF000)) & MASK
    if opcode in (0x6F, 0x67):
        return (pc + length) & MASK
    if opcode not in (0x13, 0x33):
        return None
    if opcode == 0x33 and upper == 1:
        return multiply_divide(function, left, right)
    operand = _signed(word >> 20, 12) & MASK if opcode == 0x13 else right
    amount = operand & 31
    values = {0: left - operand if opcode == 0x33 and upper == 0x20 else left + operand,
              1: left << amount, 2: int(_signed(left) < _signed(operand)),
              3: int(left < operand), 4: left ^ operand,
              5: _signed(left) >> amount if upper == 0x20 else left >> amount,
              6: left | operand, 7: left & operand}
    return values[function] & MASK


def _next_pc(record, word):
    pc, length = record["pc_rdata"], record["length"]
    opcode, function = word & 127, (word >> 12) & 7
    left, right = record["rs1_rdata"], record["rs2_rdata"]
    if word == 0x30200073:
        return record["csr_states"]["mepc"]["before"]
    if opcode == 0x6F:
        offset = ((word >> 31) << 20) | (((word >> 12) & 255) << 12) | \
            (((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1)
        return (pc + _signed(offset, 21)) & MASK
    if opcode == 0x67:
        return ((left + _signed(word >> 20, 12)) & MASK) & ~1
    if opcode == 0x63:
        conditions = {0: left == right, 1: left != right, 4: _signed(left) < _signed(right),
                      5: _signed(left) >= _signed(right), 6: left < right, 7: left >= right}
        require(function in conditions, "unknown branch condition")
        if conditions[function]:
            offset = ((word >> 31) << 12) | (((word >> 7) & 1) << 11) | \
                (((word >> 25) & 63) << 5) | (((word >> 8) & 15) << 1)
            return (pc + _signed(offset, 13)) & MASK
    return (pc + length) & MASK


def _check_csr(record, word, label, pmp):
    csr = record["csr"]
    is_csr = word is not None and word & 127 == 0x73 and (word >> 12) & 7 in (1, 2, 3, 5, 6, 7)
    require(csr["valid"] == bool(is_csr and not record["trap"]), f"{label}: CSR access validity differs")
    if not csr["valid"]:
        return
    function, source, rd = (word >> 12) & 7, (word >> 15) & 31, (word >> 7) & 31
    require(csr["address"] == word >> 20, f"{label}: CSR address differs")
    read = function not in (1, 5) or rd != 0
    require(csr["rmask"] == (MASK if read else 0), f"{label}: CSR read suppression differs")
    if function in (2, 3, 6, 7) and source == 0:
        require(csr["wmask"] == 0, f"{label}: CSR zero source has a write effect")
    if rd:
        require(record["rd_wdata"] == csr["rdata"], f"{label}: CSR result differs from observed read")
    state_name = {0x300: "mstatus", 0x341: "mepc", 0x342: "mcause", 0x343: "mtval",
                  0xB00: "mcycle", 0xB80: "mcycle", 0xC00: "mcycle", 0xC80: "mcycle",
                  0xB02: "minstret", 0xB82: "minstret", 0xC02: "minstret", 0xC82: "minstret"}.get(csr["address"])
    if state_name is not None and read:
        shift = 32 if csr["address"] & 0x80 and state_name in ("mcycle", "minstret") else 0
        require(csr["rdata"] == record["csr_states"][state_name]["before"] >> shift & MASK,
                f"{label}: CSR read differs from observed state")
    write = function in (1, 5) or source != 0
    operand = source if function >= 5 else record["rs1_rdata"]
    requested = operand if function in (1, 5) else \
        csr["rdata"] | operand if function in (2, 6) else csr["rdata"] & ~operand
    protected = bool(record["misa"] & (1 << 20))
    address = csr["address"]
    fixed_zero = address in (0x310, 0x30A, 0x31A, 0xF11, 0xF12, 0xF13, 0xF14, 0xF15) or \
        0xB03 <= address <= 0xB1F or 0xB83 <= address <= 0xB9F or 0x323 <= address <= 0x33F
    if fixed_zero or address == 0x301:
        require(csr["wmask"] == 0, f"{label}: fixed CSR has a write effect")
        expected = 0 if fixed_zero else record["misa"]
        require(csr["rdata"] == expected and csr["wdata"] == expected,
                f"{label}: fixed CSR value differs")
    elif address == 0x344 or 0xC00 <= address <= 0xC82:
        require(csr["wmask"] == 0, f"{label}: read-only CSR has a write effect")
    selected, before = pmp.read(address)
    if selected:
        require(protected, f"{label}: PMP access without U mode")
        require(csr["rdata"] == before, f"{label}: PMP read differs from its prior state")
        mask = 0
        if write:
            if 0x3A0 <= address <= 0x3A3:
                start = (address - 0x3A0) * 4
                mask = sum(0x9F << (lane * 8) for lane in range(4)
                           if not pmp.configs[start + lane] & 128)
            else:
                index = address - 0x3B0
                locked = pmp.configs[index] & 128 or \
                    index < 15 and pmp.configs[index + 1] & 0x98 == 0x88
                mask = 0 if locked else 0x3FFFFFFF
            pmp.write(address, requested)
        require(csr["wmask"] == mask, f"{label}: PMP write mask differs from lock state")
        require(csr["wdata"] == pmp.read(address)[1], f"{label}: PMP write data differs from WARL state")
    masks = {0x300: 0x221888 if protected else 0x88, 0x304: 0x888,
             0x305: 0xFFFFFFFD, 0x306: 7, 0x320: 5, 0x340: MASK,
             0x341: MASK & ~(1 if record["misa"] & 4 else 3), 0x342: MASK, 0x343: MASK,
             0xB00: MASK, 0xB80: MASK, 0xB02: MASK, 0xB82: MASK}
    if csr["address"] in masks:
        mask = masks[csr["address"]] if write else 0
        require(csr["wmask"] == mask, f"{label}: CSR write mask differs from its implemented fields")
        if csr["address"] == 0x300 and protected:
            requested = requested & ~0x1800 | (0 if requested & 0x1800 == 0 else 0x1800)
        if csr["address"] == 0x305:
            requested = requested & ~3 | int(requested & 3 == 1)
        require((csr["wdata"] ^ requested) & mask == 0, f"{label}: CSR write data differs from its operand")


def _check_state_effects(record, word, label):
    states, csr = record["csr_states"], record["csr"]
    masks = {name: 0 for name in states}
    if record["trap"]:
        masks.update(mstatus=0x1888 if record["misa"] & (1 << 20) else 0x88,
                     mepc=MASK & ~(1 if record["misa"] & 4 else 3), mcause=MASK, mtval=MASK)
    elif word == 0x30200073:
        protected = bool(record["misa"] & (1 << 20))
        masks["mstatus"] = 0x1888 if protected else 0x88
        if protected and states["mstatus"]["before"] & 0x1800 == 0:
            masks["mstatus"] |= 0x20000
    elif csr["valid"]:
        name = {0x300: "mstatus", 0x341: "mepc", 0x342: "mcause", 0x343: "mtval",
                0xB00: "mcycle", 0xB80: "mcycle", 0xB02: "minstret", 0xB82: "minstret"}.get(csr["address"])
        if name is not None:
            shift = 32 if name in ("mcycle", "minstret") and csr["address"] & 0x80 else 0
            masks[name] = csr["wmask"] << shift
            require((states[name]["after"] >> shift ^ csr["wdata"]) & csr["wmask"] == 0,
                    f"{label}: explicit CSR write differs from its state effect")
    for name, state in states.items():
        require(state["wmask"] == masks[name], f"{label}: {name} has an unauthorized state write mask")
        require((state["before"] ^ state["after"]) & ~masks[name] == 0,
                f"{label}: {name} changed without an instruction effect")


def _check_memory(record, word, label):
    if word is None or record["trap"] and record["cause"] == 2:
        require(not any(record[key] for key in ("mem_addr", "mem_rmask", "mem_wmask",
                                                "mem_rdata", "mem_wdata", "memory_operand", "memory_response",
                                                "mem_fault_rmask", "mem_fault_wmask", "memory_operation")),
                f"{label}: unavailable or illegal instruction has data-memory effects")
        if word is None:
            require(not any(record[key] for key in ("rs1_addr", "rs1_rdata", "rs2_addr", "rs2_rdata")),
                    f"{label}: unavailable instruction has source-register metadata")
        return
    opcode, function = word & 127, (word >> 12) & 7
    operation = record["memory_operation"]
    if opcode not in (0x03, 0x23, 0x2F):
        require(not any(record[key] for key in ("mem_addr", "mem_rmask", "mem_wmask", "mem_rdata",
                                                "mem_wdata", "mem_fault_rmask", "mem_fault_wmask",
                                                "memory_operation", "memory_operand", "memory_response")),
                f"{label}: nonmemory instruction has data-memory metadata")
        return
    left, right = record["rs1_rdata"], record["rs2_rdata"]
    if opcode == 0x2F:
        expected_operation = ATOMIC_OPERATIONS.get(word >> 27)
        require(function == 2 and expected_operation is not None, f"{label}: unknown atomic encoding")
        require(record["misa"] & 1, f"{label}: atomic operation without A")
        require(operation == expected_operation, f"{label}: atomic operation differs from instruction")
        address, width = left, 4
        require(record["memory_operand"] == right, f"{label}: atomic operand differs from rs2")
    else:
        require(operation == 0 and record["memory_operand"] == 0, f"{label}: ordinary access marked atomic")
        width = 1 << (function & 3)
        require(width <= 4, f"{label}: invalid access width")
        immediate = word >> 20 if opcode == 0x03 else ((word >> 25) << 5) | ((word >> 7) & 31)
        address = (left + _signed(immediate, 12)) & MASK
    mask = ((1 << width) - 1) << (address & 3)
    require(record["mem_addr"] == address & ~3, f"{label}: effective memory address differs")
    if address % width:
        require(record["trap"] and record["cause"] in (4, 6), f"{label}: unaligned access lacks alignment trap")
        return
    reads = opcode == 0x03 or operation == 1 or operation >= 3
    writes = opcode == 0x23 or operation >= 2
    if record["trap"]:
        if record["mem_fault"]:
            require(record["mem_fault_rmask"] == (mask if reads else 0) and
                    record["mem_fault_wmask"] == (mask if writes else 0),
                    f"{label}: attempted fault masks differ")
        return
    require(record["mem_rmask"] == (mask if reads else 0), f"{label}: memory read mask differs")
    write_mask = mask if writes and operation < 3 else 0
    if operation == 2:
        require(record["memory_response"] in (0, 1), f"{label}: invalid SC status")
        write_mask = mask if record["memory_response"] == 0 else 0
    require(record["mem_wmask"] == write_mask, f"{label}: memory write mask differs")
    if writes:
        require(record["mem_wdata"] == right << (8 * (address & 3)) & MASK,
                f"{label}: native write operand differs")
    if reads:
        require(record["mem_rdata"] == record["memory_response"], f"{label}: read data differs from response")
    if opcode == 0x03 and record["rd_addr"]:
        value = record["mem_rdata"] >> (8 * (address & 3)) & ((1 << (8 * width)) - 1)
        if function < 4:
            value = _signed(value, 8 * width) & MASK
        require(record["rd_wdata"] == value, f"{label}: load result differs from response lanes")
    if operation and record["rd_addr"]:
        require(record["rd_wdata"] == record["memory_response"], f"{label}: atomic result differs from response")


def _check_atomic(record, witness, label):
    require(isinstance(witness, AtomicWitness), f"{label}: expected an endpoint AtomicWitness")
    for name in ("order", "request_cycle", "commit_cycle", "response_cycle"):
        unsigned(getattr(witness, name), 64, f"{label}.witness.{name}")
    for name in ("address", "operand", "old_data", "write_data"):
        unsigned(getattr(witness, name), 32, f"{label}.witness.{name}")
    unsigned(witness.write_mask, 4, label + ".witness.write_mask")
    require(witness.owner == "data", f"{label}: endpoint witness has a different owner")
    require(witness.order == record["order"] and witness.operation == record["memory_operation"] and
            witness.address == record["mem_addr"] and witness.operand == record["memory_operand"],
            f"{label}: endpoint witness belongs to a different operation")
    require(witness.request_cycle < witness.commit_cycle <= witness.response_cycle <= record["cycle"],
            f"{label}: endpoint witness has impossible timing")
    operation, operand, old = witness.operation, witness.operand, witness.old_data
    if operation in (1, 3, 4, 5, 6, 7, 8, 9, 10, 11):
        require(old == record["mem_rdata"], f"{label}: endpoint old data differs from core response")
    expected_mask, expected_data = 0, 0
    if operation == 2:
        if record["memory_response"] == 0:
            expected_mask, expected_data = 15, operand
    elif operation >= 3:
        expected_mask = 15
        values = {3: operand, 4: old + operand, 5: old ^ operand, 6: old & operand,
                  7: old | operand, 8: min(_signed(old), _signed(operand)),
                  9: max(_signed(old), _signed(operand)), 10: min(old, operand), 11: max(old, operand)}
        expected_data = values[operation] & MASK
    require(witness.write_mask == expected_mask and
            (witness.write_data == expected_data if expected_mask else witness.write_data == 0),
            f"{label}: actual endpoint write differs from atomic semantics")


def _trap_effects(states, pc, cause, tval, mode, misa, label):
    masks = {"mstatus": 0x1888 if misa & (1 << 20) else 0x88,
             "mepc": MASK & ~(1 if misa & 4 else 3), "mcause": MASK, "mtval": MASK}
    require(all(states[name]["wmask"] == mask for name, mask in masks.items()),
            f"{label}: trap CSR write masks differ")
    before = states["mstatus"]["before"]
    after = before & ~0x88 | (before & 8) << 4
    if misa & (1 << 20):
        after = after & ~0x1800 | mode << 11
    require(states["mstatus"]["after"] == after, f"{label}: trap MSTATUS effects differ")
    require(states["mepc"]["after"] == pc and states["mcause"]["after"] == cause and
            states["mtval"]["after"] == tval, f"{label}: trap CSR effects differ")


def check_trace(records, *, reset_vector=None, interrupts=(), boundaries=(), atomic_witnesses=(),
                allow_pending_handler=False, expected_count=None):
    """Check local consistency; side events and endpoint witnesses are separate observations."""
    from pmp import Reference as PmpReference
    pmp = PmpReference()
    records = list(records)
    require(records, "trace has no retirement records")
    if expected_count is not None:
        require(type(expected_count) is int and expected_count > 0, "expected packet count must be positive")
        require(len(records) == expected_count, "retirement packet count differs")
    if reset_vector is not None:
        unsigned(reset_vector, 32, "reset vector")
    side = []
    last_interrupt = -1
    for event in interrupts:
        require(isinstance(event, Interrupt), "expected Interrupt side event")
        for key, width in (("cycle", 64), ("pc", 32), ("target", 32), ("cause", 32)):
            unsigned(getattr(event, key), width, "interrupt." + key)
        if event.csr_states is not None:
            require(type(event.mode) is int and event.mode in (0, 3), "interrupt lacks its pre-entry mode")
            _states(event.csr_states, {name: 32 for name in ("mstatus", "mepc", "mcause", "mtval")}, "interrupt states")
        require(event.cause in (0x80000003, 0x80000007, 0x8000000B), "unsupported interrupt cause")
        require(event.cycle > last_interrupt, "interrupt side events are not ordered")
        last_interrupt = event.cycle
        side.append(event)
    last_boundary = -1
    for event in boundaries:
        require(isinstance(event, Boundary) and event.kind in ("reset", "resume", "debug"),
                "unknown lifecycle boundary")
        unsigned(event.cycle, 64, "boundary.cycle")
        require(event.cycle > last_boundary, "lifecycle boundaries are not ordered")
        last_boundary = event.cycle
        require(event.pc is not None or event.kind == "debug", "boundary lacks a PC")
        if event.pc is not None:
            unsigned(event.pc, 32, "boundary.pc")
        require(event.mode is None or type(event.mode) is int and event.mode in (0, 3), "invalid boundary mode")
        require(type(event.registers) is dict, "boundary registers must be an object")
        for register, value in event.registers.items():
            unsigned(register, 5, "boundary register")
            unsigned(value, 32, "boundary value")
            require(register != 0 or value == 0, "boundary writes x0")
        side.append(event)
    side.sort(key=lambda event: event.cycle)
    require(all(a.cycle < b.cycle for a, b in zip(side, side[1:])), "duplicate or ambiguous side-event cycle")
    witnesses = list(atomic_witnesses)
    require(all(isinstance(w, AtomicWitness) for w in witnesses), "expected endpoint AtomicWitness")
    for witness in witnesses:
        unsigned(witness.epoch, 64, "witness.epoch")
        unsigned(witness.order, 64, "witness.order")
    require(len({(w.epoch, w.order) for w in witnesses}) == len(witnesses), "duplicate atomic witness order")
    witnesses = {(w.epoch, w.order): w for w in witnesses}
    registers, expected_pc, order, previous_cycle = [0] * 32, reset_vector, 0, -1
    expected_mode, pending, previous_states, index, epochs = 3, False, None, 0, 1
    expected_misa = None
    counts = Counter()
    for position, record in enumerate(records):
        label = f"packet {position}"
        validate_record(record, label)
        require(expected_misa is None or record["misa"] == expected_misa, f"{label}: configured MISA changed")
        expected_misa = record["misa"]
        cycle = record["cycle"]
        require(cycle > previous_cycle, f"{label}: cycle does not increase")
        while index < len(side) and side[index].cycle <= cycle:
            event = side[index]
            require(event.cycle < cycle, f"{label}: side event and instruction share a cycle")
            if isinstance(event, Interrupt):
                require(expected_pc is None or event.pc == expected_pc, f"{label}: interrupt PC differs")
                if event.csr_states is not None:
                    require(event.mode == expected_mode, f"{label}: interrupt pre-entry privilege differs")
                    if previous_states is not None:
                        require(all(event.csr_states[name]["before"] == previous_states[name]["after"]
                                    for name in event.csr_states), f"{label}: IRQ pre-state is disconnected")
                    _trap_effects(event.csr_states, event.pc, event.cause, 0,
                                  event.mode, record["misa"], label + " IRQ")
                    counts["irq_csr_effects"] += 1
                else:
                    counts["legacy_interrupts_without_csr_evidence"] += 1
                expected_pc, expected_mode, pending = event.target, 3, True
                previous_states = event.csr_states
                counts["interrupts"] += 1
            else:
                if event.kind == "reset":
                    registers, order, pending, expected_mode = [0] * 32, 0, False, 3
                    pmp = PmpReference()
                    epochs += 1
                registers = [event.registers.get(i, value) for i, value in enumerate(registers)]
                expected_pc = event.pc if event.pc is not None else expected_pc
                expected_mode = event.mode if event.mode is not None else expected_mode
                counts[event.kind + "_boundaries"] += 1
                previous_states = None
            index += 1
        require(record["order"] == order, f"{label}: nonconsecutive instruction order")
        require(expected_pc is None or record["pc_rdata"] == expected_pc, f"{label}: PC discontinuity lacks a real boundary")
        require(record["mode"] == expected_mode, f"{label}: privilege transition differs")
        require(record["intr"] == pending, f"{label}: trap-handler marker lacks the matching entry")
        counts["handler_markers"] += int(record["intr"])
        pending = False
        for name in ("rs1", "rs2"):
            require(record[name + "_rdata"] == registers[record[name + "_addr"]],
                    f"{label}: {name} differs from observed prior GPR state")
        word = None if record["trap"] and record["cause"] == 1 else _decoded(record)
        require(word is not None or record["trap"], f"{label}: invalid encoding did not trap")
        if word is not None and not (record["trap"] and record["cause"] == 2):
            require((record["rs1_addr"], record["rs2_addr"]) == _sources(word),
                    f"{label}: source indexes differ from standard decode")
        if word is not None and not record["trap"]:
            opcode = word & 127
            require(opcode in (0x03, 0x0F, 0x13, 0x17, 0x23, 0x2F, 0x33, 0x37, 0x63, 0x67, 0x6F, 0x73),
                    f"{label}: unsupported instruction encoding")
            writes = opcode in (0x03, 0x13, 0x17, 0x2F, 0x33, 0x37, 0x67, 0x6F) or \
                opcode == 0x73 and (word >> 12) & 7 in (1, 2, 3, 5, 6, 7)
            require(record["rd_addr"] == ((word >> 7) & 31 if writes else 0),
                    f"{label}: destination index differs from the committed write")
            require(record["pc_wdata"] == _next_pc(record, word), f"{label}: next PC differs from instruction semantics")
            result = _integer_result(word, record["rs1_rdata"], record["rs2_rdata"], record["pc_rdata"], record["length"])
            if result is not None and record["rd_addr"]:
                require(record["rd_wdata"] == result, f"{label}: integer result differs from operands")
                counts["integer_results"] += 1
        _check_csr(record, word, label, pmp)
        _check_state_effects(record, word, label)
        _check_memory(record, word, label)
        if record["memory_operation"] and not record["trap"]:
            key = epochs - 1, order
            require(key in witnesses, f"{label}: atomic operation lacks actual endpoint witness")
            _check_atomic(record, witnesses.pop(key), label)
            counts["atomic_witnesses"] += 1
        states = record["csr_states"]
        if previous_states is not None:
            for name in ("mstatus", "mepc", "mcause", "mtval"):
                require(states[name]["before"] == previous_states[name]["after"],
                        f"{label}: {name} state changed without an event")
        if record["trap"]:
            _trap_effects(states, record["pc_rdata"], record["cause"], record["tval"],
                          record["mode"], record["misa"], label)
            expected_mode, pending = 3, True
            counts["traps"] += 1
        elif word == 0x30200073:
            expected_mode = states["mstatus"]["before"] >> 11 & 3
            require(expected_mode in (0, 3), f"{label}: invalid MRET privilege")
            before = states["mstatus"]["before"]
            after = (before & ~8) | ((before >> 7 & 1) << 3) | 128
            if record["misa"] & (1 << 20):
                after &= ~0x1800
                if expected_mode == 0:
                    after &= ~(1 << 17)
            require(states["mstatus"]["after"] == after, f"{label}: MRET MSTATUS effects differ")
        registers[record["rd_addr"]] = record["rd_wdata"]
        registers[0] = 0
        expected_pc, previous_states, previous_cycle = record["pc_wdata"], states, cycle
        order += 1
        counts["packets"] += 1
    require(index == len(side), "extra side event after the trace")
    require(not witnesses, "extra endpoint witness without an instruction")
    require(allow_pending_handler or not pending, "trace ends before the first trap-handler packet")
    return {"scope": "local retirement schema, ordering and observed dataflow",
            "schema": SCHEMA, "packets": counts["packets"], "epochs": epochs,
            "counts": dict(counts), "isa_model_equivalence": False,
            "memory_contents_verified": False, "reservation_protocol_verified": False,
            "external_debug_actions_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--stdout", type=Path, help="existing execution trace containing actual N events")
    parser.add_argument("--interrupts", type=Path, help="actual IRQ JSONL sidecar with CSR effects")
    parser.add_argument("--reset-vector", type=lambda value: int(value, 0))
    parser.add_argument("--allow-pending-handler", action="store_true")
    args = parser.parse_args()
    try:
        require(not (args.stdout and args.interrupts), "select one IRQ evidence source")
        interrupts = read_interrupts(args.interrupts) if args.interrupts else \
            interrupts_from_stdout(args.stdout.read_text()) if args.stdout else ()
        result = check_trace(read_trace(args.trace), reset_vector=args.reset_vector,
                             interrupts=interrupts, allow_pending_handler=args.allow_pending_handler)
    except (TraceError, OSError, UnicodeError) as error:
        print(f"Retirement trace rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
