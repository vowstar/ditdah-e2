# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Prove shared atomic memory ownership and memory values with complete SRAM."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from atomic_memory import PORTS, configuration, digest, mutate
from core_formal import check_inputs, freeze_tools, tool_versions, write_snapshot


def wrapper(source, parameters):
    parameters = configuration(parameters)
    if parameters["sizeBytes"] > 16:
        raise ValueError("Atomic proof requires at most four SRAM words")
    bindings = [".clock(clock)", ".reset(reset)", ".clearReservation(clearReservation)"]
    bindings += [f".{name}({name})" for name in ("formalRead", "formalAddress", "formalMask", "formalWriteData", "formalReadData", "formalMemory")]
    for index, port in enumerate(PORTS):
        bindings += [f".{port}_request_valid(request_valid[{index}])", f".{port}_request_ready(request_ready[{index}])",
                     f".{port}_request_bits_address(payload[{index * 76 + 44} +: 32])",
                     f".{port}_request_bits_machine(payload[{index * 76 + 43}])",
                     f".{port}_request_bits_write(payload[{index * 76 + 42}])",
                     f".{port}_request_bits_data(payload[{index * 76 + 10} +: 32])",
                     f".{port}_request_bits_mask(payload[{index * 76 + 6} +: 4])",
                     f".{port}_request_bits_size(payload[{index * 76 + 4} +: 2])",
                     f".{port}_request_bits_operation(payload[{index * 76} +: 4])",
                     f".{port}_response_valid(response_valid[{index}])", f".{port}_response_ready(response_ready[{index}])",
                     f".{port}_response_bits_data(response_data[{index * 32} +: 32])", f".{port}_response_bits_fault(response_fault[{index}])"]
    replacements = {"@BASE@": f"32'h{parameters['baseAddress']:08x}", "@WORDS@": str(parameters["sizeBytes"] // 4),
                    "@INDEX_HIGH@": str(max(1, (parameters["sizeBytes"] // 4 - 1).bit_length()) - 1),
                    "@INSTANCE@": "DitDahE2AtomicMemory dut(\n    " + ",\n    ".join(bindings) + "\n  );"}
    for before, after in replacements.items():
        if source.count(before) != (2 if before == "@INDEX_HIGH@" else 1):
            raise ValueError("Atomic formal template changed")
        source = source.replace(before, after)
    return source


def observe(controller, storage, parameters):
    if "formalMemory" in controller + storage or controller.count(") memory (") != 1:
        raise ValueError("Atomic SRAM observation boundary changed")
    start = controller.index(") memory (")
    end = controller.index("\n  );", start)
    instance = controller[start:end]
    expressions = {}
    for name in ("address", "readEnable", "writeMask", "writeData", "readData"):
        match = re.search(r"\." + name + r"\s*\(", instance)
        if match is None:
            raise ValueError("Atomic SRAM port is absent")
        depth, position = 1, match.end()
        while depth:
            depth += (instance[position] == "(") - (instance[position] == ")")
            position += 1
        expressions[name] = instance[match.end():position - 1]
    words = parameters["sizeBytes"] // 4
    width = max(1, (words - 1).bit_length())
    declarations = (",\n  output formalRead,\n  output [" + str(width - 1) + ":0] formalAddress,\n"
                    "  output [3:0] formalMask,\n  output [31:0] formalWriteData, formalReadData,\n"
                    "  output [" + str(words * 32 - 1) + ":0] formalMemory\n);")
    controller = controller[:end] + ",\n    .formalMemory(formalMemory)" + controller[end:]
    controller = controller.replace("\n);", declarations, 1)
    assignments = "\n".join("  assign " + output + " = " + expressions[name] + ";" for output, name in
                             (("formalRead", "readEnable"), ("formalAddress", "address"), ("formalMask", "writeMask"),
                              ("formalWriteData", "writeData"), ("formalReadData", "readData")))
    controller = controller.replace("endmodule", assignments + "\nendmodule")
    declaration = "  output reg [31:0] readData\n"
    if storage.count(declaration) != 1:
        raise ValueError("Atomic SRAM output declaration changed")
    storage = storage.replace(declaration, "  output reg [31:0] readData,\n  output wire [WORDS*32-1:0] formalMemory\n")
    storage = storage.replace("endmodule", "  generate for (genvar word = 0; word < WORDS; word = word + 1) begin\n"
                              "    assign formalMemory[word*32 +: 32] = memory[word];\n  end endgenerate\nendmodule")
    return controller, storage


def ownership_wrapper(source, parameters, all_operations=False):
    header = "module atomic_memory_formal(input clock);"
    assert source.count(header) == 1 and source.count("endmodule") == 1, "Changed atomic proof top"
    source = source.replace(header, f"module atomic_memory_formal(input clock, output [{21 if all_operations else 1}:0] reach, "
                            f"output [{parameters['sizeBytes'] * 8 - 1}:0] coverMemory);")
    goal = "coverGoals" if all_operations else ("{initialized && invalidators == 7 && clear_seen && competing_write_seen, "
                                              "initialized && response_valid == 15 && response_ready == 0}")
    return source.replace("endmodule", f"assign reach = {goal};\nassign coverMemory = formalMemory;\nendmodule")


def trace_frames(content):
    names, widths, values = {}, {}, {}
    stamp = 0
    for line in content.splitlines():
        fields = line.split()
        if fields and fields[0] == "$var":
            name = fields[4].lstrip("\\")
            names[name], widths[name] = fields[3], int(fields[2])
        elif line.startswith("b"):
            bits, code = fields[0][1:], fields[1]
            values[code] = None if any(bit in bits for bit in "xz") else int(bits, 2)
        elif line and line[0] in "01xz":
            values[line[1:]] = int(line[0]) if line[0] in "01" else None
        elif line.startswith("#"):
            yield stamp, {name: values.get(code) for name, code in names.items()}, widths
            stamp = int(line[1:])
    yield stamp, {name: values.get(code) for name, code in names.items()}, widths


def ownership_trace(content):
    _, observed, widths = list(trace_frames(content))[-1]
    assert observed["reach"] == 3 and observed["response_valid"] == 15 and observed["response_ready"] == 0, "Missing ownership goals"
    assert observed["coverMemory"] is not None and widths.get("coverMemory", 0) >= 32, "Missing complete SRAM observation"
    return observed


def negative_trace(content, mutation):
    fields = ("initialized", "formalMask", "formalWriteData", "commit_write", "mask", "new_value", "operation", "address", "owner", "reservation")
    for stamp, values, _ in trace_frames(content):
        row = {name: values.get(name) for name in fields}
        if any(value is None for value in row.values()) or not row["initialized"] or row["owner"] != 1:
            continue
        expected_mask = row["mask"] if row["commit_write"] else 0
        wrong_sc = row["operation"] == 2 and row["formalMask"] != 0 and row["formalMask"] != expected_mask
        wrong_add = row["operation"] == 4 and row["formalMask"] != 0 and row["formalWriteData"] != row["new_value"]
        if wrong_sc if mutation == "stale-reservation" else wrong_add:
            return {"time": stamp, "expectedMask": expected_mask, **row}
    raise AssertionError("Missing physical write counterexample")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists(), "Atomic proof output already exists"
    build = json.loads((args.rtl / "build.json").read_text())
    assert build["exitStatus"] == 0, "Atomic generation did not pass"
    contents = {"build.json": (args.rtl / "build.json").read_bytes()}
    for group, prefix in (("inputHashes", "inputs"), ("rtlHashes", "rtl")):
        for name, expected in build[group].items():
            data = (args.rtl / prefix / name).read_bytes()
            assert hashlib.sha256(data).hexdigest() == expected, "Changed atomic proof input"
            contents[prefix + "/" + name] = data
    for path in (args.rtl / "inputs/generated").rglob("*"):
        if path.is_file():
            contents[str(path.relative_to(args.rtl))] = path.read_bytes()
    for name in ("atomic_memory_formal.py", "atomic_memory_formal.sv", "test_atomic_memory_formal.py", "core_formal.py", "atomic_memory.py"):
        contents["test/" + name] = Path(__file__).with_name(name).read_bytes()
    proof = wrapper(contents["test/atomic_memory_formal.sv"].decode(), build["parameters"])
    args.output.mkdir(parents=True)
    frozen = write_snapshot(args.output, contents)
    tools, tool_hashes = freeze_tools()
    outcomes = []
    for name, mode in (("safety", "prove"), ("ownership-cover", "cover"), ("stale-reservation", "bmc"),
                       ("amo-subtract", "bmc"), ("cover", "cover")):
        case = args.output / name
        case.mkdir()
        rtl = contents["rtl/DitDahE2AtomicMemory.sv"].decode()
        if mode == "bmc":
            rtl = mutate(rtl, name)
        rtl, storage = observe(rtl, contents["rtl/AtomicSram.sv"].decode(), build["parameters"])
        (case / "DitDahE2AtomicMemory.sv").write_text(rtl)
        (case / "AtomicSram.sv").write_text(storage)
        (case / "atomic_memory_formal.sv").write_text(ownership_wrapper(proof, build["parameters"], name == "cover") if mode == "cover" else proof)
        engine = "abc pdr" if mode == "prove" else "yosys sat"
        define = " -D REACHABILITY" if mode == "cover" else ""
        if name == "ownership-cover":
            define += " -D OWNERSHIP_COVER"
        settings = (f"[options]\nmode {mode}\ndepth 48\ntimeout 900\naigsmt z3\n[engines]\n{engine}\n"
                    f"[script]\nread -formal -sv{define} DitDahE2AtomicMemory.sv AtomicSram.sv atomic_memory_formal.sv\n"
                    "prep -top atomic_memory_formal\n[files]\nDitDahE2AtomicMemory.sv\nAtomicSram.sv\natomic_memory_formal.sv\n")
        command = ["sby", "-f", "run.sby"]
        if mode != "prove":
            settings = (f"read -formal -sv{define} DitDahE2AtomicMemory.sv AtomicSram.sv atomic_memory_formal.sv\n"
                        "prep -top atomic_memory_formal -flatten\n" + ("chformal -assert -remove\n" if mode == "cover" else "") +
                        "chformal -cover -remove\nasync2sync\nchformal -lower\nmemory_map\nopt_clean\n")
            if name == "ownership-cover":
                settings += ("sat -seq 48 -timeout 900 -set-assumes -set-at 48 reach 3 "
                             "-show reach,scenario,source_valid,accepted,returned,response_valid,response_ready,coverMemory -dump_vcd trace.vcd\n")
            elif name == "cover":
                settings += "".join(f"sat -seq 24 -timeout 900 -set-assumes -set-at 24 reach[{index}] 1 "
                                    f"-show reach,coverMemory -dump_vcd trace{index}.vcd\n" for index in range(22))
            else:
                settings += ("sat -seq 24 -timeout 900 -set-assumes -prove-asserts -falsify "
                             "-show initialized,formalMask,formalWriteData,commit_write,mask,new_value,operation,address,owner,reservation,formalMemory "
                             "-dump_vcd trace.vcd\n")
            (case / "run.ys").write_text(settings)
            command = ["yosys", "-Q", "-T", "-s", "run.ys"]
        else:
            (case / "run.sby").write_text(settings)
        candidate = {path.name: path.read_bytes() for path in case.iterdir() if path.is_file()}
        original = {path: hashlib.sha256(data).hexdigest() for path, data in candidate.items()}
        run = subprocess.run(command, cwd=case, capture_output=True, text=True)
        log = run.stdout + run.stderr
        (case / "run.log").write_text(log)
        status_path = case / "run/status"
        status = status_path.read_text().split()[0] if status_path.exists() else "ERROR"
        traces = list((case / "run/engine_0").glob("trace*.*"))
        witness = None
        if mode != "prove":
            traces = list(case.glob("trace*.vcd"))
            status = "SAT" if run.returncode == 0 and "SAT solving finished - model found:" in log else "ERROR"
            if mode == "bmc":
                status = "COUNTEREXAMPLE" if run.returncode == 0 and "SAT proof finished - model found: FAIL!" in log else "ERROR"
            if status != "ERROR":
                if name == "ownership-cover":
                    assert len(traces) == 1, "Missing ownership witness"
                    witness = ownership_trace(traces[0].read_text())
                elif name == "cover":
                    assert len(traces) == 22 and log.count("SAT solving finished - model found:") == 22, "Missing operation witnesses"
                    witness = []
                    for index in range(22):
                        _, values, _ = list(trace_frames((case / f"trace{index}.vcd").read_text()))[-1]
                        assert values.get("reach", 0) & (1 << index) and values.get("coverMemory") is not None, "Missing operation goal"
                        witness.append({"goal": index, "reach": values["reach"], "coverMemory": values["coverMemory"]})
                else:
                    assert len(traces) == 1, "Missing faulty RTL witness"
                    witness = negative_trace(traces[0].read_text(), name)
        assert all((case / name).read_bytes() == data for name, data in candidate.items()), "Atomic proof source changed"
        outcomes.append({"name": name, "mode": mode, "engine": engine, "status": status, "exitStatus": run.returncode,
                         "command": command, "witness": witness,
                         "inputHashes": original, "traceHashes": {path.name: digest(path) for path in traces}})
        (args.output / "outcomes.json").write_text(json.dumps(outcomes, indent=2) + "\n")
        expected = ("PASS", 0) if mode == "prove" else ("SAT", 0) if mode == "cover" else ("COUNTEREXAMPLE", 0)
        assert (status, run.returncode) == expected, f"{name}: {status}"
        if mode == "bmc":
            assert any(path.suffix == ".vcd" for path in traces), "Missing atomic counterexample"
    check_inputs(frozen)
    check_inputs(tools)
    summary = {"exitStatus": 0, "scope": "unbounded atomic SRAM safety", "parameters": build["parameters"],
               "inputHashes": {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
               "toolHashes": tool_hashes, **tool_versions(), "outcomes": outcomes,
               "assumptions": ["initial cold reset", "real debug-port initialization of every SRAM word", "held requests remain stable"],
               "observations": ["read-only SRAM port and memory-content outputs", "memory-content invariants are asserted, never assumed"],
               "coverStimulus": "fixed base address, full words, operand 0x80000001, arbitrary operation and handshake timing",
               "ownershipCoverStimulus": "LR and SC, LR and debug write, LR and competitor write, clear, four blocked responses",
               "initialMemory": "no reset value, compare written bytes during real port initialization, check all read values after initialization",
               "limits": ["the bound SRAM configuration", "no promise for reads before the first write", "no eventual response-ready assumption", "no CPU or PMP proof"]}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    artifacts = {str(path.relative_to(args.output)): digest(path) for path in sorted(args.output.rglob("*")) if path.is_file()}
    (args.output / "artifacts.json").write_text(json.dumps(artifacts, indent=2) + "\n")
    print("PASS: atomic safety, reachable operations and two RTL counterexamples")


if __name__ == "__main__":
    main()
