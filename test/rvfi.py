# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Run pinned external RVFI checks against the generated core."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import time
import traceback

from core_formal import source_hashes

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_REVISION = "2aa7b4934190baeb2ef62b2de414f104b489d3cc"
UPSTREAM_NAR_HASH = "sha256-LpkuVlVDknzO0xk8hXVYVmvHeAy8UMMfT3bSjQY5Lg8="
FAMILIES = ("insn", "consistency", "bus", "csr", "contract", "cover", "negative")
CSR_NAMES = ("misa", "mstatus", "mepc", "mcause", "mtval", "mcycle", "minstret",
             "mscratch", "mvendorid", "marchid", "mimpid", "mhartid", "mconfigptr")
M_INSTRUCTIONS = ("mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu")
CSRC_ANY_HASH = "62b196ab5a14f8d532d3a26666fcec9a082b708061aabab2f9dea0cc87243373"
BUS_IMEM_HASH = "a623f3f85979c656264b814727320130b8818cde80a56b88aebc4e7cec714ec0"
DISABLED_COVER_SOURCES = {
    "bus_imem_fault_ch0": ("rvfi_bus_imem_fault_check.sv", 55, 1),
    "bus_dmem_fault_ch0": ("rvfi_bus_dmem_fault_check.sv", 72, 0),
}
ACTIVE_PROCESSES = {}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def select_isa(parameters):
    if parameters["enableA"]:
        raise ValueError("The pinned native instruction models do not implement A")
    if parameters["enableDebug"]:
        raise ValueError("Native reg/PC checks require a profile without debugger intervention")
    bits = [parameters[key] for key in ("enableZba", "enableZbb", "enableZbs")]
    if any(bits):
        if not all(bits):
            raise ValueError("Partial B profiles require a separate MISA compatibility contract")
        if parameters["enableM"] or parameters["enableC"]:
            raise ValueError("Use a separate full-B native profile with M and C disabled")
        return "rv32ib"
    return "rv32i" + ("m" if parameters["enableM"] else "") + ("c" if parameters["enableC"] else "")


def read_manifest(rtl, source_root=ROOT):
    manifest = json.loads((rtl / "manifest.json").read_text())
    if manifest["sourceHashes"] != source_hashes(source_root):
        raise ValueError("Generated RTL source inputs differ from the selected source root")
    if any(digest(rtl / name) != value for name, value in manifest["rtlHashes"].items()):
        raise ValueError("Generated RTL hash differs from its manifest")
    parameters = manifest["parameters"]
    if parameters["resetVector"] != 0:
        raise ValueError("Native formal profiles require resetVector=0")
    select_isa(parameters)
    return manifest


def task_status(directory, process_status, expected="PASS"):
    status_path = directory / "status"
    raw = status_path.read_text().strip() if status_path.is_file() else "MISSING"
    match = re.fullmatch(r"(PASS|FAIL|UNKNOWN|ERROR|TIMEOUT)(?:\s+\d+\s+\d+)?", raw)
    status = match[1] if match else raw
    if process_status is None:
        return status, False
    return status, process_status == 0 and status == expected


def check_task_set(expected, actual):
    if len(expected) != len(set(expected)) or len(actual) != len(set(actual)):
        raise ValueError("Duplicate external RVFI task")
    if not expected or set(expected) != set(actual):
        raise ValueError("External RVFI task set differs from its expected manifest")


def select_tasks(expected, requested):
    if requested is None:
        return expected
    if len(requested) != len(set(requested)) or set(requested) - set(expected):
        raise ValueError("Requested RVFI task is unknown or duplicated")
    return [task for task in expected if task in requested]


def m_operand_wrapper(text, instruction):
    if instruction not in M_INSTRUCTIONS:
        raise ValueError("The operand bootstrap requires one native M instruction")
    instruction_word = 0x022081b3 | (M_INSTRUCTIONS.index(instruction) << 12)
    substitutions = {
        "rvfi_memory instruction_peer (": "rvfi_m_memory instruction_peer (",
        "rvfi_memory data_peer (": "rvfi_m_memory #(.DATA(1)) data_peer (",
        ".bus_wdata(data_bus_wdata)": ".bus_wdata(data_bus_wdata),\n"
            "        .operand_left(m_operand_left), .operand_right(m_operand_right)",
    }
    for old, new in substitutions.items():
        if text.count(old) != 1:
            raise ValueError("The operand bootstrap no longer matches the base adapter")
        text = text.replace(old, new)
    marker = "    wire interrupt_valid;"
    if text.count(marker) != 1 or text.count("endmodule") != 1:
        raise ValueError("Unexpected base adapter module boundaries")
    text = text.replace(marker, "    wire [31:0] m_operand_left, m_operand_right;\n" + marker)
    checks = """    always @(posedge clock) if (!reset && rvfi_valid && rvfi_pc_rdata == 8) begin
        assert(rvfi_insn == `DITDAH_E2_RVFI_M_INSN);
        assert(rvfi_rs1_rdata == m_operand_left);
        assert(rvfi_rs2_rdata == m_operand_right);
        assert(!rvfi_trap);
    end
"""
    return text.replace("endmodule", checks + "endmodule"), instruction_word


def csrc_identity_compatibility(suite):
    path = suite / "checks/rvfi_csrc_any_check.sv"
    if digest(path) != CSRC_ANY_HASH:
        raise ValueError("The CSR identity correction requires the pinned original checker")
    original = path.read_text()
    old = "wire csr_insn_under_test = (csr_insn_addr =="
    new = "wire csr_insn_under_test = csr_insn_addr != csr_none && (csr_insn_addr =="
    if original.count(old) != 1:
        raise ValueError("The pinned CSR identity predicate no longer matches")
    adjusted = original.replace(old, new)
    old_valid = "wire csr_insn_valid = rvfi.valid &&"
    if adjusted.count(old_valid) != 1:
        raise ValueError("The pinned CSR sample-valid predicate no longer matches")
    adjusted = adjusted.replace(old_valid, "wire csr_insn_valid = rvfi.valid && !rvfi.trap &&")
    evidence = suite / "compatibility"
    evidence.mkdir()
    (evidence / "rvfi_csrc_any_check.original.sv").write_text(original)
    (evidence / "csrc-identity.diff").write_text("".join(difflib.unified_diff(
        original.splitlines(keepends=True), adjusted.splitlines(keepends=True),
        fromfile="rvfi_csrc_any_check.original.sv", tofile="rvfi_csrc_any_check.sv")))
    path.chmod(path.stat().st_mode | 0o200)
    path.write_text(adjusted)
    return {"file": "checks/rvfi_csrc_any_check.sv", "originalSha256": CSRC_ANY_HASH,
            "adjustedSha256": digest(path),
            "changes": ["exclude absent-alias sentinel from CSR identity", "exclude trapped instructions from stateful CSR samples"],
            "reason": "Real FFF and U-mode mscratch traps have no committed CSR read or write; independent guards check their zero effects",
            "assertionsChanged": False, "environmentConstraintsAdded": False}


def csr_guard_wrapper(text, control=None):
    if text.count("endmodule") != 1 or control not in (None, "legal-value", "illegal-write"):
        raise ValueError("Unexpected CSR guard adapter or negative control")
    write_mask = "retire_csr_writeMask"
    if control == "legal-value":
        old = "assign rvfi_csr_mscratch_rdata = retire_csr_valid && retire_csr_address == 12'h340 ? retire_csr_readData : 0;"
        if text.count(old) != 1:
            raise ValueError("The legal CSR value control no longer matches")
        text = text.replace(old, old.replace("? retire_csr_readData :", "? (retire_csr_readData ^ 32'd1) :"))
    if control == "illegal-write":
        write_mask += " | ((retire_valid && retire_trap && retire_insn[6:0] == 7'h73 && retire_insn[13:12] != 0) ? 32'd1 : 0)"
    guard = f"""`ifdef DITDAH_E2_RVFI_CSR_GUARD
`ifdef RISCV_FORMAL_ILL_CSR_ADDR
    generate if (`RISCV_FORMAL_ILL_CSR_ADDR == 12'hfff) begin: illegal_effects
    rvfi_csr_guard csr_guard (
        .clock(clock), .reset(reset), .valid(retire_valid), .trap(retire_trap),
        .insn(retire_insn), .rd_data(rvfi_rd_wdata),
        .rd(rvfi_rd_addr), .cause(retire_cause), .mode(rvfi_mode),
        .command_valid(retire_csr_valid), .read_mask(retire_csr_readMask),
        .write_mask({write_mask})
    );
    end endgenerate
`endif
`endif
"""
    return text.replace("endmodule", guard + "endmodule")


def imem_fault_compatibility(suite):
    path = suite / "checks/rvfi_bus_imem_check.sv"
    if digest(path) != BUS_IMEM_HASH:
        raise ValueError("The instruction-fault correction requires the pinned original checker")
    original = path.read_text()
    marker = "\tinteger channel_idx, i, j;"
    predicate = "if (rvfi_valid[`RISCV_FORMAL_CHANNEL_IDX]) begin"
    if original.count(marker) != 1 or original.count(predicate) != 1:
        raise ValueError("The pinned instruction-data checker no longer matches")
    wire = """`ifdef RISCV_FORMAL_MEM_FAULT
    wire typed_ifetch_fault = rvfi_mem_fault[`RISCV_FORMAL_CHANNEL_IDX] &&
        !(|rvfi_mem_fault_rmask[`RISCV_FORMAL_CHANNEL_IDX*(`RISCV_FORMAL_XLEN/8) +: (`RISCV_FORMAL_XLEN/8)]) &&
        !(|rvfi_mem_fault_wmask[`RISCV_FORMAL_CHANNEL_IDX*(`RISCV_FORMAL_XLEN/8) +: (`RISCV_FORMAL_XLEN/8)]);
`else
    wire typed_ifetch_fault = 0;
`endif
"""
    adjusted = original.replace(marker, wire + marker).replace(
        predicate, predicate.replace("]) begin", "] && !typed_ifetch_fault) begin"))
    evidence = suite / "compatibility"
    evidence.mkdir(exist_ok=True)
    (evidence / "rvfi_bus_imem_check.original.sv").write_text(original)
    (evidence / "imem-fault.diff").write_text("".join(difflib.unified_diff(
        original.splitlines(keepends=True), adjusted.splitlines(keepends=True),
        fromfile="rvfi_bus_imem_check.original.sv", tofile="rvfi_bus_imem_check.sv")))
    path.chmod(path.stat().st_mode | 0o200)
    path.write_text(adjusted)
    return {"file": "checks/rvfi_bus_imem_check.sv", "originalSha256": BUS_IMEM_HASH,
            "adjustedSha256": digest(path), "change": "exclude typed instruction-fetch faults from instruction-data comparison",
            "reason": "Local PMP rejection can retire insn=0 without an external failed fetch",
            "genericTrapExcluded": False, "environmentConstraintsAdded": False,
            "companion": "rvfi_fault_check and rvfi_fault_guard"}


def fault_guard_wrapper(text, control=None):
    if text.count("endmodule") != 1 or control not in (None, "data-value", "fault-effect", "fault-cause"):
        raise ValueError("Unexpected fetch-fault guard adapter or control")
    if control == "data-value":
        old = "assign rvfi_insn = retire_insn;"
        if text.count(old) != 1:
            raise ValueError("Instruction-data control no longer matches")
        text = text.replace(old, "assign rvfi_insn = retire_insn ^ (retire_memoryFault ? 32'd0 : 32'd1);")
    typed = "(retire_memoryFault && !(|retire_faultReadMask) && !(|retire_faultWriteMask))"
    cause = "retire_cause" + (f" ^ ({typed} ? 32'd1 : 0)" if control == "fault-cause" else "")
    rmask = "retire_memoryReadMask" + (f" | ({typed} ? 4'd1 : 0)" if control == "fault-effect" else "")
    guard = f"""`ifdef DITDAH_E2_RVFI_FAULT_GUARD
    rvfi_fault_guard fault_guard (
        .clock(clock), .reset(reset), .valid(retire_valid), .trap(retire_trap),
        .mem_fault(retire_memoryFault), .fault_rmask(retire_faultReadMask),
        .fault_wmask(retire_faultWriteMask), .normal_rmask({rmask}),
        .normal_wmask(retire_memoryWriteMask), .insn(retire_insn), .cause({cause}),
        .rd(rvfi_rd_addr), .rd_data(rvfi_rd_wdata), .command_valid(retire_csr_valid),
        .csr_read_mask(retire_csr_readMask), .csr_write_mask(retire_csr_writeMask)
    );
`endif
"""
    return text.replace("endmodule", guard + "endmodule")


def reachability_wrapper(text):
    if text.count("endmodule") != 1:
        raise ValueError("Unexpected reachability adapter module boundary")
    goal = """    reg [7:0] reach_cycle = 0;
    always @(posedge clock) begin
        reach_cycle <= reset ? 8'd1 : reach_cycle + (reach_cycle != 8'hff);
        if (!reset && reach_cycle == `RISCV_FORMAL_CHECK_CYCLE)
            assert(!(rvfi_valid && !rvfi_trap));
    end
"""
    return text.replace("endmodule", goal + "endmodule")


def reachability_scope(baseline, core, task):
    prior_core = baseline / "inputs/riscv-formal/cores/ditdah_e2"
    old_task = prior_core / "checks_insn_cover" / (task + ".sby")
    new_task = core / "checks_insn" / (task + ".sby")
    old, new = old_task.read_text(), new_task.read_text()
    if "mode cover\n" not in old:
        raise ValueError("Reachability baseline is not a native cover task")
    if old.split("[file defines.sv]\n", 1)[1] != new.split("[file defines.sv]\n", 1)[1]:
        raise ValueError("Native cover defines or embedded checker inputs changed")
    old_script = old.split("[script]\n", 1)[1].split("\n[files]", 1)[0]
    new_script = new.split("[script]\n", 1)[1].split("\n[files]", 1)[0]
    if old_script.replace(str(prior_core), "CORE") != new_script.replace(str(core), "CORE"):
        raise ValueError("Native cover compilation changed")
    bindings = {str(old_task): digest(old_task)}
    for name, expected in json.loads((baseline / "summary.json").read_text())["rtlHashes"].items():
        if digest(prior_core / name) != expected or digest(core / name) != expected:
            raise ValueError("Native cover RTL bytes changed")
        bindings[str(prior_core / name)] = expected
    for old_path, new_path in ((prior_core / "rvfi_wrapper.sv", core / "rvfi_wrapper.base.sv"),
                               (prior_core / "rvfi_memory.sv", core / "rvfi_memory.sv")):
        if digest(old_path) != digest(new_path):
            raise ValueError("Native cover adapter or memory assumptions changed")
        bindings[str(old_path)] = digest(old_path)
    old_files = old.split("[files]\n", 1)[1].split("\n[file ", 1)[0].splitlines()
    new_files = new.split("[files]\n", 1)[1].split("\n[file ", 1)[0].splitlines()
    if len(old_files) != len(new_files):
        raise ValueError("Native cover source set changed")
    for left, right in zip(old_files, new_files):
        if Path(left).name != Path(right).name or digest(Path(left)) != digest(Path(right)):
            raise ValueError("Native cover checker or instruction model changed")
        bindings[left] = digest(Path(left))
    return {"nativeCoverBaseline": str(old_task), "unchangedDefinesAndAssumptions": True,
            "baselineInputHashes": bindings}


def reachability_failure(directory, wrapper):
    goal_line = next(i for i, line in enumerate(wrapper.read_text().splitlines(), 1)
                     if "assert(!(rvfi_valid && !rvfi_trap))" in line)
    failures = re.findall(r"Assert failed in rvfi_testbench: (.+?):(\d+)\.\d+-", (directory / "logfile.txt").read_text())
    if not failures or any(Path(path).resolve() != wrapper.resolve() or int(line) != goal_line
                           for path, line in failures):
        raise RuntimeError("Reachability trace also failed an original assertion or lacks the injected goal")
    return {"onlyInjectedGoalFailed": True, "source": wrapper.name, "line": goal_line}


def disabled_typed_cover_model(model, task):
    if task not in DISABLED_COVER_SOURCES or set(model["modules"]) != {"rvfi_testbench"}:
        raise ValueError("Unknown typed-channel cover model")
    top = model["modules"]["rvfi_testbench"]
    if (top["netnames"]["rvfi_bus_insn"]["bits"] != ["1", "0"] or
            top["netnames"]["rvfi_bus_data"]["bits"] != ["0", "1"]):
        raise ValueError("The disabled-cover correction requires the exact I/D channel identities")
    filename, line, channel = DISABLED_COVER_SOURCES[task]
    fault = top["netnames"]["rvfi_bus_fault"]["bits"]
    if len(fault) != 2 or any(type(bit) is not int for bit in fault) or len(set(fault)) != 2:
        raise ValueError("Unexpected typed-channel fault signals")
    removed = []
    covers = 0
    for name, cell in top["cells"].items():
        flavor = cell.get("parameters", {}).get("FLAVOR")
        if cell["type"] != "$check" or flavor != "cover":
            continue
        covers += 1
        connections = cell["connections"]
        if connections["EN"] != ["0"] and connections["A"] != ["0"]:
            continue
        source = cell.get("attributes", {}).get("src", "")
        if (not source.startswith(f"{filename}:{line}.") or connections["EN"] != ["0"] or
                connections["A"] != [fault[channel]]):
            raise ValueError("Unknown constant-false cover point must remain unresolved")
        removed.append(name)
    if len(removed) != 1:
        raise ValueError("Expected exactly one disabled typed-channel cover")
    adjusted = json.loads(json.dumps(model))
    del adjusted["modules"]["rvfi_testbench"]["cells"][removed[0]]
    validate_cover_removal(model, adjusted, removed)
    return adjusted, {"task": task, "configurationDisabled": 1, "removedCells": removed,
                      "source": filename, "line": line, "channel": channel,
                      "coversBefore": covers, "coversAfter": covers - 1,
                      "allOtherModelObjectsUnchanged": True}


def validate_cover_removal(original, adjusted, removed):
    expected = json.loads(json.dumps(original))
    if len(removed) != 1:
        raise ValueError("Unexpected disabled-cover removal set")
    for name in removed:
        cell = expected["modules"]["rvfi_testbench"]["cells"].pop(name)
        if (cell["type"] != "$check" or cell["parameters"].get("FLAVOR") != "cover" or
                cell["connections"]["EN"] != ["0"]):
            raise ValueError("The correction cannot delete an assertion, assumption or enabled cover")
    if expected != adjusted:
        raise ValueError("Disabled-cover correction changed another model object")


def prepare_native_cover_models(core, name, expected, args):
    records = {}
    for task in expected:
        if task not in DISABLED_COVER_SOURCES:
            continue
        source_file = core.parents[1] / "checks" / DISABLED_COVER_SOURCES[task][0]
        pinned_file = Path(os.environ["RISCV_FORMAL_ROOT"]) / "checks" / source_file.name
        if digest(source_file) != digest(pinned_file):
            raise ValueError("Disabled cover source differs from the pinned native checker")
        task_file = core / name / (task + ".sby")
        original = task_file.read_text()
        prepared = core / name / "typed-cover-models" / task
        prepared.mkdir(parents=True)
        task_file.with_suffix(".sby.original").write_text(original)
        work = args.output / "preparation" / name / task
        work.mkdir(parents=True)
        setup = execute(["sby", "--setup", "-f", "-d", str(work / "setup"), str(task_file)],
                        core / name, work / "setup", args.timeout)
        if setup["exitStatus"] != 0:
            raise RuntimeError("Native cover setup failed")
        script = original.split("[script]\n", 1)[1].split("\n[files]", 1)[0]
        pristine = prepared / "pristine.json"
        preparation = prepared / "prepare.ys"
        preparation.write_text(script + "\nhierarchy -smtcheck\nrename -witness\nwrite_json " + str(pristine) + "\n")
        elaborated = execute(["yosys", "-ql", str(prepared / "elaboration.log"), str(preparation)],
                             work / "setup/src", work / "elaboration", args.timeout)
        if elaborated["exitStatus"] != 0:
            raise RuntimeError("Native cover model elaboration failed")
        before = json.loads(pristine.read_text())
        after, record = disabled_typed_cover_model(before, task)
        filtered = prepared / "filtered.json"
        dump(filtered, after)
        record.update({"sourceSha256": digest(source_file), "originalModelSha256": digest(pristine),
                       "filteredModelSha256": digest(filtered)})
        dump(prepared / "model-diff.json", record)
        task_file.write_text(original.replace(script, "read_json " + str(filtered) + "\nhierarchy -top rvfi_testbench\n", 1))
        records[task] = record
    return records


def mutation(text, name):
    patterns = {
        "rd-value": ("assign rvfi_rd_wdata = retire_writes ? retire_value : 32'b0;",
                     "assign rvfi_rd_wdata = retire_writes ? (retire_value ^ 32'b1) : 32'b0;"),
        "order": ("assign rvfi_order = retire_order;", "assign rvfi_order = retire_order + 64'd1;"),
        "intr": ("assign rvfi_intr = retire_intr;", "assign rvfi_intr = 1'b1;"),
    }
    if name not in patterns:
        raise ValueError("Unknown RVFI negative control")
    old, new = patterns[name]
    if text.count(old) != 1:
        raise ValueError("RVFI mutation no longer matches exactly once")
    return text.replace(old, new)


def configuration(isa, family, depth, files, instruction=None, solver="z3", user_mode=False,
                  arithmetic_depth=None, tasks=None):
    depths = {
        "insn": [f"insn {depth}"],
        "consistency": [f"reg 1 {depth}", f"pc_fwd 1 {depth}", f"pc_bwd 1 {depth}",
                        f"unique 1 8 {depth}", f"causal 1 {depth}", f"causal_mem 1 {depth}"],
        "bus": [f"bus_imem 1 {depth}", f"bus_imem_fault 1 {depth}",
                f"bus_dmem 1 {depth}", f"bus_dmem_fault 1 {depth}", f"fault {depth}"],
        "csr": [f"csrw_mscratch {depth}", f"csrc_any_mscratch 1 {depth}", f"csr_ill {depth}",
                *[f"csrw_{name} {depth}" for name in ("mvendorid", "marchid", "mimpid", "mhartid", "mconfigptr")]],
        "contract": [f"cover 1 {depth}"],
        "cover": [f"cover 1 {depth}"],
    }
    if family not in depths:
        raise ValueError("Unknown generated RVFI family")
    if family == "insn" and arithmetic_depth is not None:
        depths[family].append(f"insn_(mul|mulh|mulhsu|mulhu|div|divu|rem|remu) {arithmetic_depth}")
    defines = ["`define YOSYS", "`define RISCV_FORMAL_ALIGNED_MEM",
               "`define RISCV_FORMAL_MEM_FAULT", "`define DITDAH_E2_RVFI_FAULTS"]
    if family == "contract":
        defines.append("`define DITDAH_E2_RVFI_CONTRACT")
    if family == "csr":
        defines.append("`define DITDAH_E2_RVFI_CSR_GUARD")
    if family == "bus":
        defines.append("`define DITDAH_E2_RVFI_FAULT_GUARD")
    if user_mode:
        defines.append("`define RISCV_FORMAL_UMODE")
    if family == "contract":
        depths[family] = [f"reg 1 {depth}"]
    csrs = [name + (" any" if name == "mscratch" else "") for name in CSR_NAMES]
    if user_mode:
        csrs += ["menvcfg const=\"32'h0\"", "menvcfgh const=\"32'h0\""]
        if family == "csr":
            depths[family] += [f"csrc_const_menvcfg 1 {depth}", f"csrc_const_menvcfgh 1 {depth}"]
    lines = ["[options]", f"isa {isa}", "nret 1", "nbus 2", "buslen 32", f"solver {solver}", "mode bmc",
             "", "[depth]", *depths[family], "", "[csrs]", *csrs,
             "", "[defines]", *defines, "", "[verilog-files]", *map(str, files)]
    if tasks is not None:
        lines += ["", "[filter-checks]", *["+ " + re.escape(task) + "$" for task in tasks], "- .*"]
    elif instruction:
        lines += ["", "[filter-checks]", f"+ insn_{re.escape(instruction)}_ch0$", "- insn_.*"]
    if family == "csr":
        lines += ["", "[illegal_csrs]", "302 m rw", "7b0 m rw", "fff " + ("mu" if user_mode else "m") + " rw"]
        if not user_mode:
            lines += ["30a m rw", "31a m rw"]
    if family == "cover":
        lines += ["", "[cover]", "always @* if (!reset) cover(rvfi_valid[0]);"]
        if user_mode:
            lines += ["always @* if (!reset) cover(rvfi_valid[0] && rvfi_mode == 0 && !rvfi_trap[0]);"]
            for address in ("30a", "31a"):
                lines += ["always @* if (!reset) cover(rvfi_valid[0] && !rvfi_trap[0] && "
                          f"rvfi_insn[31:20] == 12'h{address} && rvfi_insn[14:12] == 5 && "
                          "rvfi_insn[19:15] == 31 && rvfi_rd_addr != 0);"]
    return "\n".join(lines) + "\n"


def expected_tasks(source, isa, family, instruction=None, user_mode=False):
    if family == "insn":
        instructions = (source / f"insns/isa_{isa}.txt").read_text().split()
        if instruction and instruction not in instructions:
            raise ValueError("Requested instruction has no model in the selected ISA")
        return [f"insn_{name}_ch0" for name in sorted(instructions) if not instruction or name == instruction]
    groups = {
        "consistency": ("reg", "pc_fwd", "pc_bwd", "unique", "causal", "causal_mem"),
        "bus": ("bus_imem", "bus_imem_fault", "bus_dmem", "bus_dmem_fault", "fault"),
        "csr": ("csrw_mscratch", "csrc_any_mscratch", "csrw_mvendorid", "csrw_marchid", "csrw_mimpid", "csrw_mhartid", "csrw_mconfigptr"),
        "contract": ("reg",),
    }
    result = [name + "_ch0" for name in groups[family]] if family != "cover" else ["cover"]
    if family == "csr":
        addresses = ("302", "7b0", "fff") if user_mode else ("302", "7b0", "30a", "31a", "fff")
        result += ["csr_ill_" + address + "_ch0" for address in addresses]
        if user_mode:
            result += ["csrc_const_menvcfg_ch0", "csrc_const_menvcfgh_ch0"]
    return result


def execute(command, cwd, log, timeout):
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    ACTIVE_PROCESSES[process.pid] = process
    dump(log.with_suffix(".launch.json"), {"pid": process.pid, "command": command,
                                         "startedUnixSeconds": time.time(), "timeoutSeconds": timeout})
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        code = process.returncode
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        code = None
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        log.with_suffix(".stdout").write_text(stdout)
        log.with_suffix(".stderr").write_text(stderr)
        dump(log.with_suffix(".interrupted.json"), {
            "pid": process.pid, "childExitStatus": process.returncode,
            "elapsedSeconds": round(time.monotonic() - started, 3),
            "accepted": False, "reason": "runner interrupted"})
        ACTIVE_PROCESSES.pop(process.pid, None)
        raise
    ACTIVE_PROCESSES.pop(process.pid, None)
    log.with_suffix(".stdout").write_text(stdout)
    log.with_suffix(".stderr").write_text(stderr)
    result = {"command": command, "pid": process.pid, "exitStatus": code,
              "elapsedSeconds": round(time.monotonic() - started, 3)}
    dump(log.with_suffix(".completion.json"), result)
    return result


def configure_replay(directory, solver):
    if solver != "bmc3":
        return
    for path in directory.glob("*.sby"):
        text = path.read_text()
        if text.count("[options]\n") != 1 or "aigsmt " in text:
            raise ValueError("Unexpected native replay configuration")
        path.with_suffix(".upstream.sby").write_text(text)
        adjusted = re.sub(r"^skip \d+\n", "", text, flags=re.MULTILINE)
        path.write_text(adjusted.replace("[options]\n", "[options]\naigsmt z3\n", 1))


def run_generated(core, name, family, expected, args, expected_status="PASS"):
    generated = core / name
    actual = sorted(path.stem for path in generated.glob("*.sby") if not path.name.endswith(".upstream.sby"))
    check_task_set(expected, actual)
    baseline_scopes = ({task: reachability_scope(args.native_cover_baseline, core, task) for task in expected}
                       if args.reachability_bmc else {})
    def run(task):
        directory = args.output / "tasks" / name / task
        directory.parent.mkdir(parents=True, exist_ok=True)
        task_file = generated / (task + ".sby")
        text = task_file.read_text()
        check_cycle = re.search(r"^`define RISCV_FORMAL_CHECK_CYCLE (\d+)$", text, re.MULTILINE)
        mode = re.search(r"^mode (bmc|cover)$", text, re.MULTILINE)
        if check_cycle is None or mode is None:
            raise ValueError("Generated RVFI task has an unexpected mode or check cycle")
        command = ["sby", "-f", "-d", str(directory), str(task_file)]
        result = execute(command, generated, directory.parent / task, args.timeout)
        status, accepted = task_status(directory, result["exitStatus"], expected_status)
        raw_status = (directory / "status").read_text().strip() if (directory / "status").is_file() else "MISSING"
        record = {"task": task, "family": family, "mode": mode[1],
                "depth": int(check_cycle[1]), "nativeStatus": status, "nativeStatusRaw": raw_status,
                "accepted": accepted, "timedOut": result["exitStatus"] is None, **result}
        if mode[1] == "cover":
            smt = directory / "model/design_smt2.smt2"
            points = (re.findall(r"^; yosys-smt2-cover (\d+) (\S+) (.+)$", smt.read_text(), re.MULTILINE)
                      if smt.is_file() else [])
            log_text = (directory / "logfile.txt").read_text() if (directory / "logfile.txt").is_file() else ""
            reached = set(re.findall(r"Reached cover statement[^\n]*\(([^() ]+)\)\s*$", log_text, re.MULTILINE))
            record["coverPoints"] = [{"id": int(index), "cell": cell, "source": source,
                                      "reached": cell in reached} for index, cell, source in points]
            record["reachedCoverPointCount"] = sum(point["reached"] for point in record["coverPoints"])
            adaptation = args.cover_model_adaptations.get(task)
            if adaptation:
                record["coverModelAdaptation"] = adaptation
                record["configurationDisabled"] = adaptation["configurationDisabled"]
        if baseline_scopes:
            record["baselineScope"] = baseline_scopes[task]
        dump(directory.parent / (task + ".result.json"), record)
        print(f"RVFI {name}/{task}: {status}", flush=True)
        return record
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        return list(pool.map(run, expected))


def counterexample_witness(directory, control):
    traces = sorted(directory.glob("engine_*/trace*.vcd"))
    for trace in traces:
        scopes, signals, values = [], {}, {}
        def selected(suffix):
            matches = [value for name, code in signals.items()
                       if name.endswith(suffix) and (value := values.get(code)) is not None]
            return matches[0] if matches and len(set(matches)) == 1 else None
        def observed():
            if control == "imem-data-value":
                pc, address = selected("checker_inst.rvfi_pc_rdata"), selected("checker_inst.imem_addr")
                insn, data = selected("checker_inst.rvfi_insn"), selected("checker_inst.imem_data")
                return (selected("checker_inst.check") == selected("checker_inst.rvfi_valid") == 1
                        and selected("wrapper.retire_memoryFault") == 0
                        and None not in (pc, address, insn, data)
                        and ((pc == address and insn & 0xffff != data) or
                             (pc + 2 == address and insn & 3 == 3 and insn >> 16 != data)))
            if control in ("ifetch-fault-effect", "ifetch-fault-cause"):
                return (selected("fault_guard.valid") == selected("fault_guard.trap") ==
                        selected("fault_guard.typed_ifetch_fault") == 1 and
                        (selected("fault_guard.normal_rmask") not in (None, 0) if control.endswith("effect") else
                         selected("fault_guard.cause") not in (None, 1)))
            if control == "instruction-cover":
                return (selected("checker_inst.check") == selected("checker_inst.valid") ==
                        selected("checker_inst.spec_valid") == 1 and selected("checker_inst.trap") == 0)
            if control in ("csr-legal-value", "csr-illegal-write"):
                if control == "csr-legal-value":
                    valid, trap = selected("checker_inst.rvfi_valid"), selected("checker_inst.rvfi_trap")
                    actual, expected = selected("checker_inst.csr_insn_rdata"), selected("checker_inst.wdata_shadow")
                    return (valid == 1 and trap == 0 and selected("checker_inst.check") == 1
                            and selected("checker_inst.csr_insn_addr") == 0x340
                            and selected("checker_inst.csr_insn_rmask") == 0xffffffff
                            and selected("checker_inst.csr_written") == 1
                            and actual is not None and expected is not None and actual != expected)
                valid, trap = selected("csr_guard.valid"), selected("csr_guard.trap")
                return (valid == trap == 1 and selected("csr_guard.csr_opcode") == 1
                        and selected("csr_guard.write_mask") not in (None, 0))
            if control == "rd-value":
                valid, check = selected("checker_inst.valid"), selected("check")
                actual, expected = selected("checker_inst.rd_wdata"), selected("checker_inst.spec_rd_wdata")
                return valid == check == 1 and actual is not None and expected is not None and actual != expected
            valid = selected("wrapper.rvfi_valid")
            actual = selected("wrapper.rvfi_order" if control == "order" else "wrapper.rvfi_intr")
            expected = selected("wrapper.expected_order" if control == "order" else "wrapper.handler_pending")
            return valid == 1 and actual is not None and expected is not None and actual != expected
        for line in trace.read_text().splitlines():
            fields = line.split()
            if fields[:1] == ["$scope"]:
                scopes.append(fields[2])
            elif fields[:1] == ["$upscope"]:
                scopes.pop()
            elif fields[:1] == ["$var"]:
                signals[".".join([*scopes, fields[4]])] = fields[3]
            elif line.startswith("#"):
                if observed():
                    return {"trace": str(trace), "sha256": digest(trace),
                            **({"nativeCoverPredicatesObserved": 4} if control == "instruction-cover" else {"mismatchObserved": True})}
            elif line.startswith("b") and len(fields) == 2:
                values[fields[1]] = int(fields[0][1:], 2) if not re.search("[xz]", fields[0], re.I) else None
            elif line[:1] in ("0", "1", "x", "z"):
                values[line[1:]] = int(line[0]) if line[0] in "01" else None
        if observed():
            return {"trace": str(trace), "sha256": digest(trace),
                    **({"nativeCoverPredicatesObserved": 4} if control == "instruction-cover" else {"mismatchObserved": True})}
    raise RuntimeError("The connected negative control has no intended mismatch in its legal counterexample")


def reuse_addi_evidence(previous, manifest, wrapper, memory, tools):
    prior = json.loads((previous / "summary.json").read_text())
    if prior["rtlHashes"] != manifest["rtlHashes"]:
        raise ValueError("ADDI evidence uses different RTL")
    if prior["upstreamRevision"] != UPSTREAM_REVISION or prior["upstreamNarHash"] != UPSTREAM_NAR_HASH:
        raise ValueError("ADDI evidence uses different native properties")
    if prior["parameters"] != manifest["parameters"] or prior["isa"] != select_isa(manifest["parameters"]):
        raise ValueError("ADDI evidence uses a different profile")
    if any(prior["tools"][name]["sha256"] != tools[name]["sha256"] for name in ("yosys", "sby", "z3", "yosys-abc")):
        raise ValueError("ADDI evidence uses different proof tools")
    core = previous / "inputs/riscv-formal/cores/ditdah_e2"
    if digest(core / "rvfi_wrapper.sv") != digest(wrapper) or digest(core / "rvfi_memory.sv") != digest(memory):
        raise ValueError("ADDI evidence uses a different adapter or environment")
    record = next((row for row in prior["tasks"] if row["task"] == "insn_addi_ch0" and row["mode"] == "bmc"), None)
    if record is None or task_status(previous / "tasks/checks_insn/insn_addi_ch0", record["exitStatus"])[1] is not True:
        raise ValueError("ADDI evidence has no actual native PASS")
    return {"summarySha256": digest(previous / "summary.json"), "source": str(previous),
            "nativeStatus": "PASS", "depth": record["depth"],
            "priorRunnerAccepted": record["accepted"], "readerVerifiedActualStatus": True,
            "sourceBridge": {"priorSourceHashes": prior["sourceHashes"],
                             "currentSourceHashes": manifest["sourceHashes"],
                             "exactRtlHashesEqual": True, "adapterAndEnvironmentEqual": True}}


def run_negative_controls(core, files, source, isa, manifest, tools, args):
    positive = args.positive_addi.resolve() if args.positive_addi else args.output
    evidence = reuse_addi_evidence(positive, manifest, core / "rvfi_wrapper.sv",
                                  core / "rvfi_memory.sv", tools)
    outcomes = []
    for control in ("rd-value", "order", "intr"):
        candidate = core.with_name("ditdah_e2_negative_" + control.replace("-", "_"))
        candidate.mkdir()
        copied = []
        for path in files:
            target = candidate / path.name
            content = path.read_text()
            target.write_text(mutation(content, control) if path.name == "rvfi_wrapper.sv" else content)
            copied.append(target)
        family, instruction = ("insn", "addi") if control == "rd-value" else ("contract", None)
        name = "checks_negative_" + control.replace("-", "_")
        (candidate / (name + ".cfg")).write_text(configuration(isa, family, args.depth, copied, instruction, args.solver,
                                                            manifest["parameters"]["protectedMode"], args.arithmetic_depth))
        generated = execute([sys.executable, str(source / "checks/genchecks.py"), name], candidate,
                            args.output / (name + "-generation"), args.timeout)
        if generated["exitStatus"] != 0:
            raise RuntimeError("Negative-control task generation failed")
        configure_replay(candidate / name, args.solver)
        expected = expected_tasks(source, isa, family, instruction)
        rows = run_generated(candidate, name, "negative", expected, args, "FAIL")
        for row in rows:
            if not row["accepted"]:
                raise RuntimeError("Connected negative control did not produce the required actual FAIL")
            directory = args.output / "tasks" / name / row["task"]
            row["counterexample"] = counterexample_witness(directory, control)
            row["control"] = control
            row["positiveEvidence"] = evidence
            row["inputHashes"] = {str(path.relative_to(candidate)): digest(path)
                                  for path in candidate.rglob("*") if path.is_file()}
            outcomes.append(row)
    return outcomes


def main():
    def interrupted(signum, _frame):
        for pid in list(ACTIVE_PROCESSES):
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        raise KeyboardInterrupt(f"RVFI runner received signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, default=ROOT / "result/rtl")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--depth", type=int, default=16)
    parser.add_argument("--arithmetic-depth", type=int, default=64)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--family", action="append", choices=FAMILIES)
    parser.add_argument("--instruction")
    parser.add_argument("--task", action="append")
    parser.add_argument("--positive-addi", type=Path)
    parser.add_argument("--solver", choices=("z3", "bmc3"), default="z3")
    parser.add_argument("--environment", choices=("symbolic", "m-operands"), default="symbolic")
    parser.add_argument("--cover-only", action="store_true")
    parser.add_argument("--csr-negative", choices=("legal-value", "illegal-write"))
    parser.add_argument("--positive-csr", type=Path)
    parser.add_argument("--reachability-bmc", action="store_true")
    parser.add_argument("--native-cover-baseline", type=Path)
    parser.add_argument("--fault-negative", choices=("data-value", "fault-effect", "fault-cause"))
    parser.add_argument("--positive-fault", type=Path)
    args = parser.parse_args()
    args.cover_model_adaptations = {}
    if args.depth < 12 or args.depth > 200 or not 40 <= args.arithmetic_depth <= 200 or args.jobs < 1 or args.timeout < 1:
        parser.error("Use depth 12..200 and positive jobs/timeout")
    args.rtl, args.output = args.rtl.resolve(), args.output.resolve()
    args.source_root = args.source_root.resolve()
    manifest = read_manifest(args.rtl, args.source_root)
    manifest_hash = digest(args.rtl / "manifest.json")
    source = Path(os.environ.get("RISCV_FORMAL_ROOT", ""))
    if not source.is_dir() or not (source / "checks/genchecks.py").is_file():
        parser.error("RISCV_FORMAL_ROOT must name the pinned riscv-formal source")
    nar = subprocess.check_output(["nix", "hash", "path", "--type", "sha256", str(source)], text=True).strip()
    if nar != UPSTREAM_NAR_HASH:
        parser.error("External riscv-formal source NAR hash differs from the pinned revision")
    args.output.mkdir(parents=True, exist_ok=False)
    def preparation_failure(error_type, error, trace):
        dump(args.output / "summary.json", {
            "state": "failed", "stage": "preparation", "exitStatus": 1,
            "error": {"type": error_type.__name__, "message": str(error),
                      "traceback": "".join(traceback.format_exception(error_type, error, trace))}})
        sys.__excepthook__(error_type, error, trace)
    sys.excepthook = preparation_failure
    dump(args.output / "summary.json", {"state": "running", "stage": "preparation", "exitStatus": None})
    families = args.family or ["insn", "consistency", "bus", "csr", "contract", "cover", "negative"]
    if len(families) != len(set(families)):
        parser.error("Each RVFI family must appear once")
    if args.task and (len(families) != 1 or families[0] == "negative" or args.instruction):
        parser.error("Use --task with one non-negative family and without --instruction")
    if args.environment == "m-operands" and (families != ["insn"] or args.task or
            args.instruction not in M_INSTRUCTIONS or not manifest["parameters"]["enableM"]):
        parser.error("Use m-operands with one M-enabled native instruction family and --instruction")
    if args.cover_only and (len(families) != 1 or families[0] not in ("insn", "bus")):
        parser.error("Use --cover-only with one instruction or bus family")
    if args.reachability_bmc and (not args.cover_only or families != ["insn"] or args.solver != "bmc3"):
        parser.error("Use --reachability-bmc with --cover-only --family insn --solver bmc3")
    if args.reachability_bmc and not args.native_cover_baseline:
        parser.error("BMC reachability requires --native-cover-baseline")
    if args.csr_negative:
        if families != ["csr"] or args.task or args.instruction or not args.positive_csr:
            parser.error("Use --csr-negative with one CSR family and --positive-csr")
        args.task = ["csrc_any_mscratch_ch0" if args.csr_negative == "legal-value" else "csr_ill_fff_ch0"]
    if args.fault_negative:
        if families != ["bus"] or args.task or args.instruction or not args.positive_fault or args.cover_only:
            parser.error("Use --fault-negative with one bus family and --positive-fault")
        args.task = ["bus_imem_ch0" if args.fault_negative == "data-value" else "fault_ch0"]
    suite = args.output / "inputs/riscv-formal"
    for folder in ("checks", "insns"):
        shutil.copytree(source / folder, suite / folder)
    compatibility = []
    if manifest["parameters"]["protectedMode"] and "csr" in families:
        compatibility.append(csrc_identity_compatibility(suite))
    if "bus" in families:
        compatibility.append(imem_fault_compatibility(suite))
    core = suite / "cores/ditdah_e2"
    core.mkdir(parents=True)
    files = []
    for name in manifest["rtlHashes"]:
        target = core / name
        target.write_bytes((args.rtl / name).read_bytes())
        if digest(target) != manifest["rtlHashes"][name]:
            raise ValueError("RTL input changed during copying")
        files.append(target)
    for name in ("rvfi_wrapper.sv", "rvfi_memory.sv"):
        target = core / name
        target.write_bytes((ROOT / "test" / name).read_bytes())
        files.append(target)
    if "csr" in families:
        wrapper = core / "rvfi_wrapper.sv"
        (core / "rvfi_wrapper.base.sv").write_bytes(wrapper.read_bytes())
        wrapper.write_text(csr_guard_wrapper(wrapper.read_text(), args.csr_negative))
        target = core / "rvfi_csr_guard.sv"
        target.write_bytes((ROOT / "test/rvfi_csr_guard.sv").read_bytes())
        files.append(target)
    if "bus" in families:
        wrapper = core / "rvfi_wrapper.sv"
        (core / "rvfi_wrapper.base.sv").write_bytes(wrapper.read_bytes())
        wrapper.write_text(fault_guard_wrapper(wrapper.read_text(), args.fault_negative))
        target = core / "rvfi_fault_guard.sv"
        target.write_bytes((ROOT / "test/rvfi_fault_guard.sv").read_bytes())
        files.append(target)
    if args.reachability_bmc:
        args.native_cover_baseline = args.native_cover_baseline.resolve()
        baseline = json.loads((args.native_cover_baseline / "summary.json").read_text())
        if (baseline["parameters"] != manifest["parameters"] or baseline["rtlHashes"] != manifest["rtlHashes"] or
                baseline["upstreamRevision"] != UPSTREAM_REVISION or baseline["upstreamNarHash"] != UPSTREAM_NAR_HASH):
            raise ValueError("Native cover baseline uses different RTL or properties")
        if not args.task and not args.instruction:
            cover_groups = [group["tasks"] for group in baseline["taskManifest"] if group["group"] == "checks_insn_cover"]
            if len(cover_groups) != 1:
                raise ValueError("Native cover baseline has no unique instruction task manifest")
            args.task = cover_groups[0]
        wrapper = core / "rvfi_wrapper.sv"
        (core / "rvfi_wrapper.base.sv").write_bytes(wrapper.read_bytes())
        wrapper.write_text(reachability_wrapper(wrapper.read_text()))
    m_word = None
    if args.environment == "m-operands":
        wrapper = core / "rvfi_wrapper.sv"
        base = wrapper.read_text()
        (core / "rvfi_wrapper.base.sv").write_text(base)
        adapted, m_word = m_operand_wrapper(base, args.instruction)
        wrapper.write_text(adapted)
        target = core / "rvfi_m_memory.sv"
        target.write_bytes((ROOT / "test/rvfi_m_memory.sv").read_bytes())
        files.append(target)
    for path in (Path(__file__), ROOT / "test/test_rvfi.py", ROOT / "test/core_formal.py",
                 ROOT / "test/rvfi.sh", ROOT / "Makefile", ROOT / "nix/rvfi-tools.nix"):
        target = args.output / "inputs" / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    frozen = {path: digest(path) for path in (args.output / "inputs").rglob("*") if path.is_file()}
    for name, expected_hash in manifest["sourceHashes"].items():
        source_path = args.source_root / name
        target = args.output / "inputs/source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source_path.read_bytes())
        if digest(target) != expected_hash:
            raise ValueError("Source snapshot changed during copying")
        frozen[target] = expected_hash
    tools = {}
    for tool, options in (("yosys", ["-V"]), ("sby", ["--version"]), ("z3", ["--version"]),
                          ("yosys-abc", ["-c", "version"]), ("python3", ["--version"]), ("nix", ["--version"])):
        path = Path(shutil.which(tool))
        result = subprocess.run([str(path), *options], capture_output=True, text=True, check=True)
        tools[tool] = {"path": str(path), "sha256": digest(path), "version": (result.stdout + result.stderr).strip()}
    isa = select_isa(manifest["parameters"])
    result = {"upstreamRevision": UPSTREAM_REVISION, "upstreamNarHash": nar, "parameters": manifest["parameters"],
              "command": sys.argv,
              "isa": isa, "solver": args.solver, "tools": tools, "sourceHashes": manifest["sourceHashes"], "rtlHashes": manifest["rtlHashes"],
              "assumptions": {"initialResetOnly": True, "instructionAndDataPeers": "independent single owner ready/valid peers",
                              "responseLatency": "one through four cycles after acceptance", "requestReady": "unconstrained while idle",
                              "dataAndAccessFault": "symbolic, captured on accepted request", "interruptInputs": "tied low",
                              "debugIntervention": "disabled by profile"},
              "unsupportedNativeContracts": ["A instruction semantics", "active debug backend changes", "partial B MISA gating"],
              "generatorAdaptations": (["ABC replay solver is Z3", "SMT-only skip option removed; assertion gates unchanged"]
                                       if args.solver == "bmc3" else []),
              "requestedFamilies": families, "requestedInstruction": args.instruction,
              "requestedTasks": args.task,
              "coverModelAdaptations": [],
              "coverOnly": args.cover_only,
              "csrNegativeControl": args.csr_negative,
              "faultNegativeControl": args.fault_negative,
              "nativeBusCoverTasks": (select_tasks(expected_tasks(source, isa, "bus"), args.task)
                                      if "bus" in families and not args.fault_negative else []),
              "reachabilityMethod": "bmc-witness-of-four-native-instruction-covers" if args.reachability_bmc else "native-cover-mode",
              "checkerCompatibility": compatibility,
              "taskManifest": [], "tasks": [], "negativeControls": [],
              "state": "running", "stage": "preflight-complete", "error": None, "exitStatus": None}
    result["environment"] = args.environment
    if m_word is not None:
        result["assumptions"].update({
            "instructionAndDataPeers": "fixed two-load/M/terminal-loop ROM and operand memory",
            "responseLatency": "one cycle after acceptance", "requestReady": "unconstrained while idle",
            "dataAndAccessFault": "no access faults; two independent unconstrained 32-bit constants",
            "programWords": {"0": "10002083", "4": "10402103", "8": f"{m_word:08x}", "other": "0000006f"},
            "operandAddresses": [256, 260], "operandValueRestrictions": [],
            "instructionStreamRestricted": True, "arbitraryInstructionStreamAccepted": False})
    def record_failure(error_type, error, trace):
        result["state"] = "failed"
        result["exitStatus"] = 1
        result["error"] = {"type": error_type.__name__, "message": str(error),
                           "stage": result["stage"], "traceback": "".join(traceback.format_exception(error_type, error, trace))}
        dump(args.output / "summary.json", result)
        sys.__excepthook__(error_type, error, trace)
    sys.excepthook = record_failure
    if args.csr_negative:
        positive = args.positive_csr.resolve()
        prior = json.loads((positive / "summary.json").read_text())
        positive_core = positive / "inputs/riscv-formal/cores/ditdah_e2"
        normal_wrapper = csr_guard_wrapper((core / "rvfi_wrapper.base.sv").read_text())
        if (prior.get("state") != "accepted" or prior.get("csrNegativeControl") or
                prior["rtlHashes"] != manifest["rtlHashes"] or
                prior["checkerCompatibility"] != compatibility or
                (positive_core / "rvfi_wrapper.sv").read_text() != normal_wrapper or
                digest(positive_core / "rvfi_csr_guard.sv") != digest(core / "rvfi_csr_guard.sv") or
                digest(positive_core / "rvfi_memory.sv") != digest(core / "rvfi_memory.sv") or
                any(prior["tools"][tool]["sha256"] != tools[tool]["sha256"] for tool in tools) or
                not any(row["task"] == "csrc_any_mscratch_ch0" and row["accepted"] and
                        row["nativeStatus"] == "PASS" and row["mode"] == "bmc" for row in prior["tasks"])):
            raise ValueError("CSR negative control needs matching accepted positive evidence")
        result["csrPositiveEvidence"] = {"summary": str(positive / "summary.json"),
                                         "sha256": digest(positive / "summary.json")}
    if args.fault_negative:
        positive = args.positive_fault.resolve()
        prior = json.loads((positive / "summary.json").read_text())
        positive_core = positive / "inputs/riscv-formal/cores/ditdah_e2"
        normal_wrapper = fault_guard_wrapper((core / "rvfi_wrapper.base.sv").read_text())
        if (prior.get("state") != "accepted" or prior.get("faultNegativeControl") or
                prior["rtlHashes"] != manifest["rtlHashes"] or prior["checkerCompatibility"] != compatibility or
                (positive_core / "rvfi_wrapper.sv").read_text() != normal_wrapper or
                digest(positive_core / "rvfi_fault_guard.sv") != digest(core / "rvfi_fault_guard.sv") or
                digest(positive_core / "rvfi_memory.sv") != digest(core / "rvfi_memory.sv") or
                any(prior["tools"][tool]["sha256"] != tools[tool]["sha256"] for tool in tools) or
                not all(any(row["task"] == task and row["accepted"] and row["nativeStatus"] == "PASS" and
                            row["mode"] == "bmc" for row in prior["tasks"]) for task in ("bus_imem_ch0", "fault_ch0"))):
            raise ValueError("Fetch-fault negative control needs matching accepted positive evidence")
        result["faultPositiveEvidence"] = {"summary": str(positive / "summary.json"),
                                           "sha256": digest(positive / "summary.json")}
    dump(args.output / "summary.json", result)
    for family in families:
        if family == "negative":
            continue
        name = "checks_" + family
        result["stage"] = "generate-" + name
        dump(args.output / "summary.json", result)
        solver = "z3" if family == "cover" or (args.cover_only and not args.reachability_bmc) else args.solver
        depth = max(args.depth, 48) if family == "cover" and manifest["parameters"]["protectedMode"] else args.depth
        expected = select_tasks(expected_tasks(source, isa, family, args.instruction,
                                              manifest["parameters"]["protectedMode"]), args.task)
        config = configuration(isa, family, depth, files, args.instruction, solver,
                               manifest["parameters"]["protectedMode"], args.arithmetic_depth,
                               expected if args.task or args.cover_only else None)
        if m_word is not None:
            config = config.replace("[defines]\n", f"[defines]\n`define DITDAH_E2_RVFI_M_INSN 32'h{m_word:08x}\n", 1)
        if args.cover_only and not args.reachability_bmc:
            config = config.replace("mode bmc\n", "mode cover\n", 1)
        (core / (name + ".cfg")).write_text(config)
        generated = execute([sys.executable, str(suite / "checks/genchecks.py"), name], core,
                            args.output / (name + "-generation"), args.timeout)
        if generated["exitStatus"] != 0:
            raise RuntimeError("External RVFI task generation failed")
        configure_replay(core / name, solver)
        if args.cover_only and family == "bus":
            adapted = prepare_native_cover_models(core, name, expected, args)
            args.cover_model_adaptations.update(adapted)
            result["coverModelAdaptations"].extend(adapted.values())
        for path in (core / name).rglob("*"):
            if path.is_file():
                frozen[path] = digest(path)
        frozen[core / (name + ".cfg")] = digest(core / (name + ".cfg"))
        dump(args.output / (name + "-expected.json"), expected)
        result["taskManifest"].append({"group": name, "family": family, "tasks": expected,
                                       "mode": "cover" if family == "cover" or (args.cover_only and not args.reachability_bmc) else "bmc",
                                       "expectedNativeStatus": "FAIL" if args.csr_negative or args.fault_negative or args.reachability_bmc else "PASS"})
        result["stage"] = "run-" + name
        dump(args.output / "summary.json", result)
        rows = run_generated(core, name, family, expected, args, "FAIL" if args.csr_negative or args.fault_negative or args.reachability_bmc else "PASS")
        result["tasks"].extend(rows)
        dump(args.output / "summary.json", result)
        if not all(row["accepted"] for row in result["tasks"]):
            raise RuntimeError("An external RVFI check failed or did not produce PASS")
        if args.csr_negative:
            for row in rows:
                row["control"] = "csr-" + args.csr_negative
                row["counterexample"] = counterexample_witness(
                    args.output / "tasks" / name / row["task"], row["control"])
                result["negativeControls"].append(row)
        if args.fault_negative:
            for row in rows:
                row["control"] = "imem-data-value" if args.fault_negative == "data-value" else "ifetch-" + args.fault_negative
                row["counterexample"] = counterexample_witness(
                    args.output / "tasks" / name / row["task"], row["control"])
                result["negativeControls"].append(row)
        if args.reachability_bmc:
            for row in rows:
                scope = row.pop("baselineScope")
                directory = args.output / "tasks" / name / row["task"]
                row["reachabilityWitness"] = counterexample_witness(
                    directory, "instruction-cover")
                row["reachabilityWitness"].update(reachability_failure(directory, core / "rvfi_wrapper.sv"))
                row["reachabilityWitness"]["scopeBridge"] = scope
        if family in ("insn", "bus") and not args.cover_only and not args.fault_negative:
            reach_expected = expected
            if not reach_expected:
                continue
            reach_name = "checks_" + family + "_cover"
            result["stage"] = "generate-" + reach_name
            dump(args.output / "summary.json", result)
            reach = configuration(isa, family, args.depth, files, args.instruction, "z3",
                                  manifest["parameters"]["protectedMode"], args.arithmetic_depth,
                                  reach_expected)
            if m_word is not None:
                reach = reach.replace("[defines]\n", f"[defines]\n`define DITDAH_E2_RVFI_M_INSN 32'h{m_word:08x}\n", 1)
            (core / (reach_name + ".cfg")).write_text(reach.replace("mode bmc\n", "mode cover\n", 1))
            generated = execute([sys.executable, str(suite / "checks/genchecks.py"), reach_name], core,
                                args.output / (reach_name + "-generation"), args.timeout)
            if generated["exitStatus"] != 0:
                raise RuntimeError("Instruction reachability task generation failed")
            if family == "bus":
                adapted = prepare_native_cover_models(core, reach_name, reach_expected, args)
                args.cover_model_adaptations.update(adapted)
                result["coverModelAdaptations"].extend(adapted.values())
            for path in (core / reach_name).rglob("*"):
                if path.is_file():
                    frozen[path] = digest(path)
            frozen[core / (reach_name + ".cfg")] = digest(core / (reach_name + ".cfg"))
            dump(args.output / (reach_name + "-expected.json"), reach_expected)
            result["taskManifest"].append({"group": reach_name, "family": family + "-cover", "tasks": reach_expected,
                                           "mode": "cover"})
            result["stage"] = "run-" + reach_name
            dump(args.output / "summary.json", result)
            result["tasks"].extend(run_generated(core, reach_name, family + "-cover", reach_expected, args))
            dump(args.output / "summary.json", result)
            if not all(row["accepted"] for row in result["tasks"]):
                raise RuntimeError("A selected native instruction was not reached successfully")
    if "negative" in families:
        result["stage"] = "connected-negative-controls"
        dump(args.output / "summary.json", result)
        result["negativeControls"] = run_negative_controls(core, files, suite, isa, manifest, tools, args)
        dump(args.output / "summary.json", result)
    result["stage"] = "final-input-integrity"
    dump(args.output / "summary.json", result)
    if any(digest(path) != value for path, value in frozen.items()):
        raise RuntimeError("Frozen RVFI inputs changed during verification")
    if manifest["sourceHashes"] != source_hashes(args.source_root):
        raise RuntimeError("Selected source snapshot changed during verification")
    if digest(args.rtl / "manifest.json") != manifest_hash or any(
            digest(args.rtl / name) != value for name, value in manifest["rtlHashes"].items()):
        raise RuntimeError("Original RTL inputs changed during verification")
    if any(digest(Path(record["path"])) != record["sha256"] for record in tools.values()):
        raise RuntimeError("Proof tool changed during verification")
    if args.reachability_bmc:
        for row in result["tasks"]:
            for path, expected in row["reachabilityWitness"]["scopeBridge"]["baselineInputHashes"].items():
                if digest(Path(path)) != expected:
                    raise RuntimeError("Native cover baseline input changed during reachability checking")
    result["inputHashes"] = {str(path.relative_to(args.output)): value for path, value in frozen.items()}
    result["counts"] = {"expectedTasks": sum(len(group["tasks"]) for group in result["taskManifest"]),
                        "executedTasks": len(result["tasks"]),
                        "boundedPass": sum(row["accepted"] and row["nativeStatus"] == "PASS" and row["mode"] == "bmc" for row in result["tasks"]),
                        "coveredTasks": sum(row["accepted"] and ((row["nativeStatus"] == "PASS" and row["mode"] == "cover") or
                                            bool(row.get("reachabilityWitness"))) for row in result["tasks"]),
                        "effectiveNegativeControls": len(result["negativeControls"]), "unboundedProofs": 0}
    result["counts"]["configurationDisabledCoverPoints"] = sum(row.get("configurationDisabled", 0) for row in result["tasks"])
    result["counts"]["reachedNativeCoverPoints"] = sum(row.get("reachedCoverPointCount", 0) for row in result["tasks"])
    result["exitStatus"] = 0
    result["state"] = "accepted"
    result["stage"] = "complete"
    dump(args.output / "summary.json", result)
    print("PASS: external RVFI checks")


if __name__ == "__main__":
    main()
