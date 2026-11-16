# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Generate the AXI4-Lite adapter and check transactions from complete port traces."""

import argparse
from collections import Counter, deque
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from build_rtl import configuration
FIELDS = ("owner", "write", "address", "data", "mask", "size", "machine", "operation", "awDelay", "wDelay", "arDelay",
          "responseDelay", "nativeDelay", "response")
CHANNELS = {"i": ("ia", "iw", "id", "im", "iz", "ip", "ix"), "d": ("da", "dw", "dd", "dm", "dz", "dp", "dx"),
            "o": ("od", "of"), "p": ("pd", "pf"), "a": ("aa", "ap"),
            "w": ("wd", "wm"), "b": ("br",), "r": ("ra", "rp"), "q": ("qd", "qr")}
READY = {"i": "ir", "d": "dr", "o": "or", "p": "pr", "a": "ay", "w": "wy", "b": "by",
         "r": "ry", "q": "qy"}
WRAPPER = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, AxiLiteIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2AxiTest"
  def architecture(p: Parameters) =
    val io = summon[Interface[AxiLiteIO]]
    val unit = AxiLite.instantiate(p)
    unit.io.clock := io.clock
    unit.io.reset := io.reset
    unit.io.instruction :<>= io.instruction
    unit.io.data :<>= io.data
    io.axi :<>= unit.io.axi
"""


def vectors(seed, count=1024):
    rng = random.Random(seed)
    rows = []
    for index in range(count):
        for owner in (0, 1):
            write = owner and (index < 32 or rng.randrange(2))
            offset = index % 4
            rows.append(dict(zip(FIELDS, (owner, int(write), 0x20000000 + 4 * rng.randrange(256) + offset,
                                         rng.getrandbits(32), index % 16, index % 3, (index // 2) % 2,
                                         1 + (index // 5) % 15 if index >= 32 and index % 5 == 0 else 0,
                                         (0, 7, 3)[index % 3] if index < 32 else rng.randrange(20),
                                         (7, 0, 3)[index % 3] if index < 32 else rng.randrange(20),
                                         rng.randrange(12), rng.randrange(12), rng.randrange(12),
                                         (0, 2, 3)[index % 3])), strict=True))
    for index in range(4):
        rows.append(dict(zip(FIELDS, (0, 0, 0x20000000 + 4 * index, 0, 0, 2, 1, 0,
                                     0, 0, 0, 0, 0, (0, 2, 3, 0)[index]), strict=True)))
    for index in range(4):
        rows.append(dict(zip(FIELDS, (0, 1, 0x20000020 + 4 * index, 0x10203040 + index,
                                     (0, 1, 7, 15)[index], 2, 1, 0,
                                     index % 2, (index + 1) % 2, 0, 3, index,
                                     (0, 2, 3, 0)[index]), strict=True)))
        rows.append(dict(zip(FIELDS, (1, 0, 0x20000020 + 4 * index, 0, 0, 2, 0, 0,
                                     0, 0, index, 2, index, 0), strict=True)))
    return rows, [rng.getrandbits(32) for _ in range(256)]


def parse_trace(trace):
    lines = trace.splitlines()
    fields = lines[0].split()
    assert len(fields) == len(set(fields)), "Repeated trace field"
    rows = []
    for index, line in enumerate(lines[1:]):
        values = list(map(int, line.split()))
        assert len(values) == len(fields), f"Incomplete trace at cycle {index}"
        row = dict(zip(fields, values, strict=True))
        assert row["cycle"] == index, "Missing trace cycle"
        rows.append(row)
    return rows


def check(vectors, initial, samples, complete=True, *, concurrent=True):
    queues = [[row for row in vectors if row["owner"] == owner] for owner in (0, 1)]
    positions = [0, 0]
    memory = {0x20000000 + 4 * index + lane: (word >> (8 * lane)) & 255
              for index, word in enumerate(initial) for lane in range(4)}
    active = [None, None]
    reads, addresses, writes, write_responses = deque(), deque(), deque(), deque()
    previous = None
    counts = Counter()
    masks, offsets = set(), set()
    for sample in samples:
        cycle = sample["cycle"]
        if sample["reset"]:
            assert cycle < 2 and not any(active), "Reset during a transaction"
            assert not any(sample[name] for name in ("iv", "dv", "bv", "qv")), "Reset with an offered transaction"
            previous = None
            continue
        if previous:
            for channel, payload in CHANNELS.items():
                if previous[channel + "v"] and not previous[READY[channel]]:
                    assert sample[channel + "v"], f"Withdrawn {channel} at cycle {cycle}"
                    assert all(sample[field] == previous[field] for field in payload), f"Unstable {channel} at cycle {cycle}"
        native_completed = [False, False]
        if sum(item is not None for item in active) == 2:
            counts["overlappedActiveCycles"] += 1
        if not concurrent:
            assert sum(item is not None for item in active) <= 1, "Serial native ownership overlapped"
            assert not (sample["ov"] and sample["pv"]), "Serial native responses overlapped: wrong owner"
        if reads and write_responses:
            counts["readWriteOverlapCycles"] += 1
        if sample["qy"]:
            assert reads, "Unowned output: read response ready without an address"
        if sample["by"]:
            assert write_responses, "Unowned output: write response ready without address and data"
        for channel, key in (("a", "aw"), ("r", "ar")):
            if not sample[channel + "v"]:
                continue
            ordinary = [item for item in active if item and not item["request"]["operation"] and
                        bool(item["request"]["write"]) == (channel == "a")]
            assert ordinary or not any(item and item["request"]["operation"] for item in active), "Atomic request reached AXI"
            owner = int(not (sample[channel + "p"] & 4))
            item = active[owner]
            assert item is not None, "Unowned output: address without a native request"
            request = item["request"]
            assert not request["operation"], "Atomic request reached AXI"
            assert bool(request["write"]) == (channel == "a"), "Wrong AXI request type"
            assert cycle > item["accepted"], "External request before native acceptance"
            assert item[key] is None and item["response"] is None, "Repeated AXI request channel"
            assert (sample[channel + "a"], sample[channel + "p"]) == (
                request["address"] & ~3, (0 if owner else 4) | request["machine"]), "Wrong address or protection"
            if sample[READY[channel]]:
                item[key] = cycle
                counts[key + "Transfers"] += 1
                if channel == "a":
                    addresses.append(owner)
                else:
                    reads.append((owner, cycle))
            else:
                counts[key + "Stalls"] += 1
        if sample["wv"]:
            assert any(item and item["request"]["write"] and not item["request"]["operation"] for item in active), \
                "Atomic request reached AXI" if any(active) else "Unowned output: write data"
            if sample["wy"]:
                writes.append((cycle, sample["wd"], sample["wm"]))
                masks.add(sample["wm"])
                counts["wTransfers"] += 1
            else:
                counts["wStalls"] += 1
        while addresses and writes:
            owner = addresses.popleft()
            accepted, value, mask = writes.popleft()
            item = active[owner]
            request = item["request"]
            assert item["w"] is None and item["response"] is None, "Repeated AXI request channel"
            assert (value, mask) == (request["data"], request["mask"]), "Changed write payload"
            item["w"] = accepted
            if request["response"] == 0:
                address = request["address"] & ~3
                for lane in range(4):
                    if mask & (1 << lane):
                        memory[address + lane] = (value >> (8 * lane)) & 255
            write_responses.append((owner, cycle))
        # The endpoint snapshots reads at AR acceptance, after simultaneous completed writes.
        for owner, accepted in reads:
            item = active[owner]
            if accepted == cycle:
                address = item["request"]["address"] & ~3
                item["readValue"] = sum(memory[address + lane] << (8 * lane) for lane in range(4))
        if len(reads) == 2:
            counts["twoReadOutstandingCycles"] += 1
        for channel, pending in (("b", write_responses), ("q", reads)):
            if not sample[channel + "v"]:
                continue
            assert sample[channel + "r"] != 1, "AXI4-Lite forbids EXOKAY"
            assert pending, "Unowned output: AXI response without a request"
            owner, issued = pending[0]
            item = active[owner]
            request = item["request"]
            assert issued < cycle, "Early AXI response"
            assert item["response"] is None, "Duplicate AXI response"
            assert sample[channel + "r"] == request["response"], "Changed response code"
            if channel == "q":
                assert sample["qd"] == item["readValue"], "Read data differs from byte memory"
            if sample[READY[channel]]:
                pending.popleft()
                value = 0 if channel == "b" else item["readValue"]
                item["response"] = (cycle, value, int(request["response"] != 0))
                counts["axiResponses"] += 1
                if channel == "b":
                    order = "awFirst" if item["aw"] < item["w"] else "wFirst" if item["w"] < item["aw"] else "awTogether"
                    counts[order] += 1
        for owner, channel in enumerate(("o", "p")):
            item = active[owner]
            if sample[channel + "v"]:
                assert item is not None, "Unowned output: response delivered to wrong owner"
                assert item["response"] is not None, "Response delivered to wrong owner or before AXI result"
                request = item["request"]
                responded, value, fault = item["response"]
                assert item["accepted"] < cycle, "Native response before request ownership"
                assert responded <= cycle, "Native response before AXI result"
                assert (sample[channel + "d"], sample[channel + "f"]) == (value, fault), "Wrong native response"
                if responded == cycle and not request["operation"]:
                    counts["bypassResponses"] += 1
                    counts["faultBypassResponses"] += fault
                if sample[READY[channel]]:
                    native_completed[owner] = True
                    counts["responses"] += 1
                    counts[f"owner{owner}Rejected{request['operation']}" if request["operation"] else
                           f"owner{owner}Code{request['response']}"] += 1
                    active[owner] = None
                else:
                    counts["nativeResponseStalls"] += 1
            if item is not None and not native_completed[owner]:
                assert not sample["dr" if owner else "ir"], "Request accepted before native completion"
        accepted = [owner for owner, channel in enumerate(("i", "d"))
                    if sample[channel + "v"] and sample[READY[channel]]]
        if not concurrent:
            assert len(accepted) <= 1 and sum(item is not None for item in active) + len(accepted) <= 1, "Serial native acceptance overlapped"
        counts["parallelAcceptCycles"] += int(len(accepted) == 2)
        for owner in accepted:
            assert active[owner] is None, "Second outstanding native request on one port"
            assert positions[owner] < len(queues[owner]), "Extra native request"
            row = queues[owner][positions[owner]]
            prefix = "d" if owner else "i"
            assert tuple(sample[prefix + field] for field in ("a", "w", "d", "m", "z", "p", "x")) == tuple(
                row[field] for field in ("address", "write", "data", "mask", "size", "machine", "operation")), "Changed native request"
            if sample["iv"] and sample["dv"]:
                counts["contendedGrants"] += 1
            if native_completed[owner]:
                counts["replacementTransfers"] += 1
                counts["sameOwnerReplacements"] += 1
            elif native_completed[1 - owner]:
                counts["replacementTransfers"] += 1
                counts["otherOwnerReplacements"] += 1
            positions[owner] += 1
            active[owner] = {"request": row, "accepted": cycle, "aw": None, "w": None, "ar": None,
                             "response": (cycle, 0, 1) if row["operation"] else None}
            counts["requests"] += 1
            offsets.add(row["address"] % 4)
        previous = sample
    if complete:
        assert not any(active), "Unfinished native request"
        assert not reads and not addresses and not writes and not write_responses, "Unfinished AXI transaction"
        assert positions == list(map(len, queues)), "Unaccepted test requests"
        assert counts["responses"] == len(vectors), "Missing native completion"
    return {**counts, "writeMasks": sorted(masks), "addressOffsets": sorted(offsets), "cycles": len(samples)}

def expected_ports():
    expected = {"clock": ("input", 1), "reset": ("input", 1)}
    for port in ("instruction", "data"):
        for name, direction, width in (("request_valid", "input", 1), ("request_ready", "output", 1),
                                       ("response_valid", "output", 1), ("response_ready", "input", 1),
                                       ("response_bits_data", "output", 32), ("response_bits_fault", "output", 1)):
            expected[port + "_" + name] = direction, width
        for name, width in (("address", 32), ("machine", 1), ("write", 1), ("data", 32),
                            ("mask", 4), ("size", 2), ("operation", 4)):
            expected[port + "_request_bits_" + name] = "input", width
    for channel, master, payload in (("aw", True, (("address", 32), ("protection", 3))),
                                     ("w", True, (("data", 32), ("strobe", 4))),
                                     ("b", False, (("response", 2),)),
                                     ("ar", True, (("address", 32), ("protection", 3))),
                                     ("r", False, (("data", 32), ("response", 2)))):
        direction = "output" if master else "input"
        expected[f"axi_{channel}_valid"] = direction, 1
        expected[f"axi_{channel}_ready"] = "input" if master else "output", 1
        for name, width in payload:
            expected[f"axi_{channel}_bits_{name}"] = direction, width
    return expected


def check_axi_structure(design):
    module = design["modules"]["DitDahE2AxiLite"]
    ports = module["ports"]
    expected = expected_ports()
    assert {name: (port["direction"], len(port["bits"])) for name, port in ports.items()} == expected, "Flattened AXI ABI changed"
    reached = {bit for name, port in ports.items() if name.startswith("axi_") and port["direction"] == "input"
               for bit in port["bits"] if isinstance(bit, int)}
    sequential = ("$dff", "$adff", "$sdff", "$dlatch", "$aldff")
    changed = True
    while changed:
        changed = False
        for cell in module["cells"].values():
            if cell["type"].startswith(sequential):
                continue
            inputs = {bit for name, bits in cell["connections"].items() if cell["port_directions"][name] == "input" for bit in bits}
            if not reached.intersection(inputs):
                continue
            outputs = {bit for name, bits in cell["connections"].items() if cell["port_directions"][name] == "output" for bit in bits if isinstance(bit, int)}
            if outputs - reached:
                reached.update(outputs)
                changed = True
    for name, port in ports.items():
        if name.startswith("axi_") and port["direction"] == "output":
            assert not reached.intersection(port["bits"]), f"AXI combinational input-to-output path reaches {name}"
    return {"portCount": len(ports), "axiInputToOutputCombinationalPaths": 0}


def negative_controls(rows, initial, samples, *, concurrent=True):
    first = next(index for index in range(len(samples) - 1, -1, -1)
                 if bool(samples[index]["ov"]) != bool(samples[index]["pv"]))
    wrong = [dict(row) for row in samples[:first + 1]]
    wrong[-1]["pv" if wrong[-1]["ov"] else "ov"] = 1
    duplicate = [dict(row) for row in samples[-1:]]
    duplicate[0]["ov"] = duplicate[0]["or"] = 1
    bad_code = [dict(row) for row in samples]
    response = next(row for row in bad_code if row["bv"] or row["qv"])
    response["br" if response["bv"] else "qr"] = 1
    for name, trace, expected in (("wrong-owner", wrong, "wrong owner"),
                                  ("duplicate-response", duplicate, "Unowned output"),
                                  ("exokay", bad_code, "EXOKAY")):
        try:
            check(rows, initial, trace, complete=False, concurrent=concurrent)
        except AssertionError as error:
            assert expected in str(error), f"Wrong negative control failure: {error}"
        else:
            raise AssertionError(f"Accepted {name} negative control")
    return ["wrong-owner", "duplicate-response", "exokay"]


def sha(value):
    return hashlib.sha256(value).hexdigest()


def freeze(root, destination):
    names = ["ditdah_e2/src/" + name for name in ("AxiLite.scala", "AxiLiteInterfaces.scala", "Interfaces.scala",
                                               "Parameters.scala", "DebugTransportInterfaces.scala")]
    names += ["test/test_platform/axi.py", "test/test_platform/axi_sim.cpp", "test/test_platform/test_axi.py",
              "scripts/build_rtl.py", "flake.nix", "flake.lock"]
    names += [str(path.relative_to(root)) for path in sorted((root / "nix").glob("*.nix"))]
    contents = {name: (root / name).read_bytes() for name in names}
    for name, value in contents.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    return contents


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/axi"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--seed", type=int, action="append")
    args = parser.parse_args()
    parameters = configuration(json.loads(args.config.read_text()) if args.config else {})
    concurrent = parameters.get("axiConcurrent", False)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    commands = []
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-axi-", dir=scratch) as directory:
        work = Path(directory)
        contents = freeze(ROOT, work / "inputs")
        shutil.copytree(work / "inputs", output / "inputs", dirs_exist_ok=True)
        source = work / "inputs/ditdah_e2/src"
        (source / "AxiTop.scala").write_text(WRAPPER)
        (work / "parameters.json").write_text(json.dumps(parameters) + "\n")
        (output / "parameters.json").write_text(json.dumps(parameters) + "\n")
        env = dict(os.environ, DITDAH_E2_SOURCE=str(source))

        def run(command):
            result = subprocess.run(command, cwd=work, env=env, capture_output=True, text=True)
            commands.append({"argv": command, "exitStatus": result.returncode})
            if result.returncode:
                raise RuntimeError((result.stdout + result.stderr).replace(str(work), "<workspace>"))
            return result.stdout

        run(["elaborate-ditdah-e2", "design", "parameters.json"])
        run(["firld", *[path.name for path in sorted(work.glob("*.mlirbc"))], "--base-circuit", "DitDahE2AxiTest",
             "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"])
        run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
             "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"])
        rtl = sorted((work / "rtl").glob("*.sv"))
        for path in rtl:
            shutil.copyfile(path, output / path.name)
        run(["yosys", "-Q", "-T", "-p", "read_verilog -sv " + " ".join(str(path.relative_to(work)) for path in rtl) +
             "; hierarchy -check -top DitDahE2AxiLite; proc; opt_clean; write_json structure.json"])
        structure = check_axi_structure(json.loads((work / "structure.json").read_text()))
        shutil.copyfile(work / "structure.json", output / "structure.json")
        run(["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2AxiLite",
             "-Wno-fatal", *[str(path.relative_to(work)) for path in rtl], "inputs/test/test_platform/axi_sim.cpp"])
        outcomes = []
        for seed in args.seed or (7, 19, 2026):
            rows, initial = vectors(seed)
            vector_text = "".join(" ".join(str(row[name]) for name in FIELDS) + "\n" for row in rows)
            memory_text = "\n".join(map(str, initial)) + "\n"
            (work / "vectors.txt").write_text(vector_text)
            (work / "memory.txt").write_text(memory_text)
            trace = run(["obj_dir/VDitDahE2AxiLite", "vectors.txt", "memory.txt"])
            (output / f"seed-{seed}.trace").write_text(trace)
            (output / f"seed-{seed}.vectors").write_text(vector_text)
            (output / f"seed-{seed}.memory").write_text(memory_text)
            samples = parse_trace(trace)
            counts = check(rows, initial, samples, concurrent=concurrent)
            controls = negative_controls(rows, initial, samples, concurrent=concurrent)
            for name in ("awFirst", "wFirst", "awTogether", "nativeResponseStalls", "awStalls", "wStalls", "arStalls"):
                assert counts[name] > 0, f"Unreached scenario {name}"
            assert counts["writeMasks"] == list(range(16)), "Missing write mask"
            assert counts["addressOffsets"] == list(range(4)), "Missing address offset"
            overlap = ("parallelAcceptCycles", "overlappedActiveCycles", "twoReadOutstandingCycles", "readWriteOverlapCycles")
            if concurrent:
                assert all(counts.get(name, 0) > 0 for name in overlap), "Missing concurrent schedule"
            else:
                assert not any(counts.get(name, 0) for name in overlap), "Serial adapter overlapped transactions"
            for name in ("bypassResponses", "faultBypassResponses", "replacementTransfers", "sameOwnerReplacements"):
                assert counts[name] > 0, f"Unreached scenario {name}"
            assert all(counts[f"owner{owner}Code{code}"] > 0 for owner in (0, 1) for code in (0, 2, 3)), "Missing response class"
            assert all(counts[f"owner{owner}Rejected{op}"] > 0 for owner in (0, 1) for op in range(1, 16)), "Missing rejected operation"
            outcomes.append({"seed": seed, **counts, "negativeControls": controls,
                             "vectorHash": sha(vector_text.encode()), "memoryHash": sha(memory_text.encode()), "traceHash": sha(trace.encode())})
        assert all((work / "inputs" / name).read_bytes() == value for name, value in contents.items()), "Frozen inputs changed"
        tools = {name: run(command).strip() for name, command in (("firtool", ["firtool", "--version"]),
                 ("firld", ["firld", "--version"]), ("verilator", ["verilator", "--version"]),
                 ("yosys", ["yosys", "-V"]), ("cxx", ["c++", "--version"]))}
        tools["cxx"] = tools["cxx"].splitlines()[0]
        report = {"scope": "standalone dual native port to AXI4-Lite adapter", "parameters": parameters,
                  "inputHashes": {name: sha(value) for name, value in contents.items()},
                  "rtlHashes": {path.name: sha(path.read_bytes()) for path in rtl}, "wrapperHash": sha(WRAPPER.encode()),
                  "tools": tools, "elaboratorHash": sha(Path(shutil.which("elaborate-ditdah-e2")).read_bytes()),
                  "commands": commands, "command": "python3 test/test_platform/axi.py", "exitStatus": 0, "outcomes": outcomes,
                  "structure": structure,
                  "environment": ["cold reset before offered requests", "one outstanding native request per port",
                                  "AXI4-Lite responses are OKAY, SLVERR or DECERR", "failed writes have no memory effect",
                                  "responses preserve order within each AXI direction",
                                  "reads snapshot at AR acceptance after completed same-cycle write pairs"],
                  "excluded": ["CPU integration", "platform endpoints", "atomic memory execution", "warm reset", "memory liveness"]}
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {sum(row['responses'] for row in outcomes)} AXI transactions and {3 * len(outcomes)} negative controls")


if __name__ == "__main__":
    main()
