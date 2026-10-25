# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Generate the AXI4-Lite adapter and check transactions from complete port traces."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
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


def check(vectors, initial, samples, complete=True):
    queues = [[row for row in vectors if row["owner"] == owner] for owner in (0, 1)]
    positions = [0, 0]
    memory = {0x20000000 + 4 * index + lane: (word >> (8 * lane)) & 255
              for index, word in enumerate(initial) for lane in range(4)}
    active = None
    previous = None
    prefer = 0
    counts = Counter()
    masks = set()
    offsets = set()
    for sample in samples:
        cycle = sample["cycle"]
        if sample["reset"]:
            assert cycle < 2 and active is None, "Reset during a transaction"
            assert not any(sample[name] for name in ("iv", "dv", "bv", "qv")), "Reset with an offered transaction"
            previous = None
            continue
        if previous:
            for channel, payload in CHANNELS.items():
                if previous[channel + "v"] and not previous[READY[channel]]:
                    assert sample[channel + "v"], f"Withdrawn {channel} at cycle {cycle}"
                    assert all(sample[field] == previous[field] for field in payload), f"Unstable {channel} at cycle {cycle}"
        if active:
            assert not sample["ir"] and not sample["dr"], "Request accepted before native completion"
        else:
            assert not any(sample[name] for name in ("av", "wv", "rv", "by", "qy", "ov", "pv")), "Unowned output"
        accepted = [owner for owner, channel in enumerate(("i", "d"))
                    if sample[channel + "v"] and sample[READY[channel]]]
        assert len(accepted) <= 1, "Two native requests accepted"
        if accepted:
            assert active is None, "Second outstanding native request"
            owner = accepted[0]
            assert positions[owner] < len(queues[owner]), "Extra native request"
            row = queues[owner][positions[owner]]
            prefix = "d" if owner else "i"
            assert tuple(sample[prefix + field] for field in ("a", "w", "d", "m", "z", "p", "x")) == tuple(
                row[field] for field in ("address", "write", "data", "mask", "size", "machine", "operation")), "Changed native request"
            if sample["iv"] and sample["dv"]:
                assert owner == prefer, "Arbitration did not alternate"
                counts["contendedGrants"] += 1
            prefer = 1 - owner
            positions[owner] += 1
            active = {"request": row, "accepted": cycle, "aw": None, "w": None, "ar": None, "response": (cycle, 0, 1) if row["operation"] else None}
            counts["requests"] += 1
            offsets.add(row["address"] % 4)
        if active:
            request = active["request"]
            if request["operation"]:
                assert not any(sample[key] for key in ("av", "wv", "rv", "by", "qy")), "Atomic request reached AXI"
            write = request["write"]
            address = request["address"] & ~3
            prot = (0 if request["owner"] else 4) | request["machine"]
            for channel, key in (("a", "aw"), ("w", "w"), ("r", "ar")):
                if not sample[channel + "v"]:
                    continue
                assert cycle > active["accepted"], "External request before native acceptance"
                assert active[key] is None and active["response"] is None, "Repeated AXI request channel"
                assert bool(write) == (channel != "r"), "Wrong AXI request type"
                if channel == "w":
                    assert (sample["wd"], sample["wm"]) == (request["data"], request["mask"]), "Changed write payload"
                else:
                    assert (sample[channel + "a"], sample[channel + "p"]) == (address, prot), "Wrong address or protection"
                if sample[READY[channel]]:
                    active[key] = cycle
                    counts[key + "Transfers"] += 1
                    if channel == "w":
                        masks.add(sample["wm"])
                else:
                    counts[key + "Stalls"] += 1
            for channel in ("b", "q"):
                if not sample[channel + "v"]:
                    continue
                assert sample[channel + "r"] != 1, "AXI4-Lite forbids EXOKAY"
                assert bool(write) == (channel == "b"), "Response type differs"
                prerequisites = (active["aw"], active["w"]) if write else (active["ar"],)
                assert all(value is not None and value < cycle for value in prerequisites), "Early AXI response"
                assert active["response"] is None, "Duplicate AXI response"
                assert sample[channel + "r"] == request["response"], "Changed response code"
                if sample[READY[channel]]:
                    value = 0
                    if write:
                        if request["response"] == 0:
                            for lane in range(4):
                                if request["mask"] & (1 << lane):
                                    memory[address + lane] = (request["data"] >> (8 * lane)) & 255
                        order = "awFirst" if active["aw"] < active["w"] else "wFirst" if active["w"] < active["aw"] else "awTogether"
                        counts[order] += 1
                    else:
                        value = sum(memory[address + lane] << (8 * lane) for lane in range(4))
                        assert sample["qd"] == value, "Read data differs from byte memory"
                    active["response"] = (cycle, value, int(request["response"] != 0))
                    counts["axiResponses"] += 1
            for owner, channel in enumerate(("o", "p")):
                if not sample[channel + "v"]:
                    continue
                assert owner == request["owner"], "Response delivered to wrong owner"
                assert active["response"] is not None, "Native response before AXI response"
                responded, value, fault = active["response"]
                assert responded < cycle, "Native response before captured result"
                assert (sample[channel + "d"], sample[channel + "f"]) == (value, fault), "Wrong native response"
                if sample[READY[channel]]:
                    counts["responses"] += 1
                    if request["operation"]:
                        counts[f"owner{owner}Rejected{request['operation']}"] += 1
                    else:
                        counts[f"owner{owner}Code{request['response']}"] += 1
                    active = None
                else:
                    counts["nativeResponseStalls"] += 1
        previous = sample
    if complete:
        assert active is None, "Unfinished native request"
        assert positions == list(map(len, queues)), "Unaccepted test requests"
        assert counts["responses"] == len(vectors), "Missing native completion"
    return {**counts, "writeMasks": sorted(masks), "addressOffsets": sorted(offsets), "cycles": len(samples)}


def negative_controls(rows, initial, samples):
    first = next(index for index, row in enumerate(samples) if row["ov"] or row["pv"])
    wrong = [dict(row) for row in samples[:first + 1]]
    wrong[-1]["ov"], wrong[-1]["pv"] = wrong[-1]["pv"], wrong[-1]["ov"]
    duplicate = [dict(row) for row in samples[-1:]]
    duplicate[0]["ov"] = duplicate[0]["or"] = 1
    bad_code = [dict(row) for row in samples]
    response = next(row for row in bad_code if row["bv"] or row["qv"])
    response["br" if response["bv"] else "qr"] = 1
    for name, trace, expected in (("wrong-owner", wrong, "wrong owner"),
                                  ("duplicate-response", duplicate, "Unowned output"),
                                  ("exokay", bad_code, "EXOKAY")):
        try:
            check(rows, initial, trace, complete=False)
        except AssertionError as error:
            assert expected in str(error), f"Wrong negative control failure: {error}"
        else:
            raise AssertionError(f"Accepted {name} negative control")
    return ["wrong-owner", "duplicate-response", "exokay"]


def sha(value):
    return hashlib.sha256(value).hexdigest()


def freeze(root, destination):
    names = ["ditdah_e2/src/" + name for name in ("AxiLite.scala", "AxiLiteInterfaces.scala", "Interfaces.scala", "Parameters.scala")]
    names += ["test/axi.py", "test/axi_sim.cpp", "flake.nix", "flake.lock"]
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
    parser.add_argument("--seed", type=int, action="append")
    args = parser.parse_args()
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
        (work / "parameters.json").write_text('{"resetVector":0}\n')
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
        run(["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", "DitDahE2AxiLite",
             "-Wno-fatal", *[str(path.relative_to(work)) for path in rtl], "inputs/test/axi_sim.cpp"])
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
            counts = check(rows, initial, samples)
            controls = negative_controls(rows, initial, samples)
            for name in ("awFirst", "wFirst", "awTogether", "nativeResponseStalls", "awStalls", "wStalls", "arStalls"):
                assert counts[name] > 0, f"Unreached scenario {name}"
            assert counts["writeMasks"] == list(range(16)), "Missing write mask"
            assert counts["addressOffsets"] == list(range(4)), "Missing address offset"
            assert counts["contendedGrants"] == len(rows) - 1, "Missing sustained contention"
            assert all(counts[f"owner{owner}Code{code}"] > 0 for owner in (0, 1) for code in (0, 2, 3)), "Missing response class"
            assert all(counts[f"owner{owner}Rejected{op}"] > 0 for owner in (0, 1) for op in range(1, 16)), "Missing rejected operation"
            outcomes.append({"seed": seed, **counts, "negativeControls": controls,
                             "vectorHash": sha(vector_text.encode()), "memoryHash": sha(memory_text.encode()), "traceHash": sha(trace.encode())})
        assert all((work / "inputs" / name).read_bytes() == value for name, value in contents.items()), "Frozen inputs changed"
        tools = {name: run(command).strip() for name, command in (("firtool", ["firtool", "--version"]),
                 ("firld", ["firld", "--version"]), ("verilator", ["verilator", "--version"]), ("cxx", ["c++", "--version"]))}
        tools["cxx"] = tools["cxx"].splitlines()[0]
        report = {"scope": "standalone dual native port to AXI4-Lite adapter", "parameters": {"resetVector": 0},
                  "inputHashes": {name: sha(value) for name, value in contents.items()},
                  "rtlHashes": {path.name: sha(path.read_bytes()) for path in rtl}, "wrapperHash": sha(WRAPPER.encode()),
                  "tools": tools, "elaboratorHash": sha(Path(shutil.which("elaborate-ditdah-e2")).read_bytes()),
                  "commands": commands, "command": "python3 test/axi.py", "exitStatus": 0, "outcomes": outcomes,
                  "environment": ["cold reset before offered requests", "one outstanding native request per port",
                                  "AXI4-Lite responses are OKAY, SLVERR or DECERR", "failed writes have no memory effect"],
                  "excluded": ["CPU integration", "platform endpoints", "atomic memory execution", "warm reset", "memory liveness"]}
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {sum(row['responses'] for row in outcomes)} AXI transactions and {3 * len(outcomes)} negative controls")


if __name__ == "__main__":
    main()
