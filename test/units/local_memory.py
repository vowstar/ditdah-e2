# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check local SRAM transactions against an independent byte-memory history."""

import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
TOP = "DitDahE2LocalMemoryBench"
REQUEST = ("address", "write", "data", "mask", "size", "machine", "operation")
FIELDS = ("cycle", "reset", "phase") + tuple(
    f"{port}_{channel}_{field}" for port in ("instruction", "data")
    for channel, payload in (("request", REQUEST), ("response", ("data", "fault")))
    for field in ("valid", "ready", *payload))
CASES = tuple({"name": f"{words}-words-latency-{latency}", "baseAddress": base,
               "sizeBytes": words * 4, "readLatency": latency}
              for latency in (1, 2) for words, base in ((1, 0xFFFFFFFC), (3, 0x20000000),
                                                      (4096, 0x10000), (8192, 0x20010000)))


def request(address, *, owner=1, phase=1, write=0, data=0, mask=0, size=2, machine=1, operation=0):
    return dict(phase=phase, owner=owner, address=address, write=write, data=data,
                mask=mask, size=size, machine=machine, operation=operation)


def legal(parameters, owner, item):
    width = 1 << item["size"]
    address = item["address"]
    if item["size"] > 2 or address % width or item["operation"]:
        return False
    mask = ((1 << width) - 1) << (address % 4) if item["write"] else 0
    return (parameters["baseAddress"] <= address < parameters["baseAddress"] + parameters["sizeBytes"]
            and item["mask"] == mask and (owner == 1 or not item["write"] and width == 4))


def vectors(parameters, seed=2026, count=256):
    rng = random.Random(seed)
    base, words = parameters["baseAddress"], parameters["sizeBytes"] // 4
    rows = [request(base + 4 * index, phase=0, write=1, mask=15, data=rng.getrandbits(32))
            for index in range(words)]
    for owner in (0, 1):
        indices = sorted({0, words - 1, *[index for index in (1, 2, 3, 2047, 2048, 4095, 4096) if index < words]})
        rows += [request(base + 4 * index, owner=owner) for index in indices]
        for lane in range(4):
            for size in range(4):
                for write in (0, 1):
                    for mask in range(16):
                        rows.append(request(base + lane, owner=owner, write=write, mask=mask, size=size,
                                            data=rng.getrandbits(32)))
        for address in ((base - 4) & 0xFFFFFFFF, (base + parameters["sizeBytes"]) & 0xFFFFFFFF):
            rows.append(request(address, owner=owner, write=1, mask=15, data=rng.getrandbits(32)))
            rows.append(request(address, owner=owner))
        for operation in range(1, 16):
            rows.append(request(base, owner=owner, operation=operation, write=1, mask=15, data=rng.getrandbits(32)))
        for index in range(count):
            address = base + 4 * rng.randrange(words) + rng.randrange(4)
            size, write = rng.randrange(4), rng.randrange(2)
            mask = rng.randrange(16)
            if index % 3:
                size = 2 if owner == 0 else rng.randrange(3)
                address &= ~((1 << size) - 1)
                write = write if owner else 0
                mask = ((1 << (1 << size)) - 1) << (address % 4) if write else 0
            rows.append(request(address, owner=owner, size=size, write=write, mask=mask,
                                data=rng.getrandbits(32), machine=index % 2))
    rows += [request(base, owner=0) for _ in range(4)]
    denied_fetch_writes = []
    for size, lane in ((0, 0), (0, 1), (0, 2), (0, 3), (1, 0), (1, 2), (2, 0)):
        denied_fetch_writes += [request(base + lane, owner=0, phase=2, write=1, size=size,
                                       mask=((1 << (1 << size)) - 1) << lane, data=rng.getrandbits(32)),
                                request(base, owner=0, phase=2)]
    rows += denied_fetch_writes
    # This interval has no legal writer, so later valid stores cannot hide a rejected write.
    rows += [request(base, phase=2) for _ in denied_fetch_writes]
    invalid = [request(address, phase=2, write=1, mask=15, data=rng.getrandbits(32))
               for address in ((base - 4) & 0xFFFFFFFF, (base + parameters["sizeBytes"]) & 0xFFFFFFFF)]
    invalid += [request(base + 1, phase=2, write=1, mask=15, data=rng.getrandbits(32)),
                request(base, phase=2, write=1, mask=1, data=rng.getrandbits(32)),
                request(base, phase=2, write=1, size=3, mask=15, data=rng.getrandbits(32))]
    invalid += [request(base, phase=2, write=1, mask=15, operation=operation, data=rng.getrandbits(32))
                for operation in range(1, 16)]
    for item in invalid:
        rows += [item, request(base, phase=2), request(base + parameters["sizeBytes"] - 4, phase=2)]
    rows += [request(base + 4 * index, phase=2) for index in range(words)]
    return rows


def parse_trace(lines):
    iterator = iter(lines)
    assert next(iterator).split() == list(FIELDS), "Unexpected local-memory trace fields"
    for cycle, line in enumerate(iterator):
        values = list(map(int, line.split()))
        assert len(values) == len(FIELDS), "Incomplete local-memory trace"
        row = dict(zip(FIELDS, values, strict=True))
        assert row["cycle"] == cycle, "Missing local-memory cycle"
        yield row


def check(parameters, requests, samples, complete=True):
    queues = [[item for item in requests if item["owner"] == owner] for owner in (0, 1)]
    positions = [0, 0]
    memory = {}
    readback = set()
    pending = previous = None
    prefer = 0
    counts = Counter()
    for sample in samples:
        cycle = sample["cycle"]
        if sample["reset"]:
            assert pending is None, "Reset before transaction drained"
            assert not any(sample[f"{port}_request_valid"] for port in ("instruction", "data")), "Reset with offered request"
            assert not any(sample[f"{port}_response_valid"] for port in ("instruction", "data")), "Response during quiescent reset"
            counts["resetCycles"] += 1
            prefer, previous = 0, None
            continue
        if previous:
            for port in ("instruction", "data"):
                if previous[f"{port}_request_valid"] and not previous[f"{port}_request_ready"]:
                    assert sample[f"{port}_request_valid"], "Withdrawn local-memory request"
                    assert all(sample[f"{port}_request_{field}"] == previous[f"{port}_request_{field}"] for field in REQUEST), "Changed held request"
        finished = False
        for owner, port in enumerate(("instruction", "data")):
            valid = sample[f"{port}_response_valid"]
            expected = pending is not None and pending["owner"] == owner and cycle >= pending["due"]
            assert bool(valid) == expected, "Wrong response owner or latency"
            if valid:
                assert (sample[f"{port}_response_data"], sample[f"{port}_response_fault"]) == (pending["data"], pending["fault"]), "Wrong local-memory response"
                if sample[f"{port}_response_ready"]:
                    counts["responses"] += 1
                    counts[f"owner{owner}Responses"] += 1
                    finished = True
                else:
                    counts["responseStalls"] += 1
        old = pending
        if finished:
            pending = None
        accepted = [owner for owner, port in enumerate(("instruction", "data"))
                    if sample[f"{port}_request_valid"] and sample[f"{port}_request_ready"]]
        assert len(accepted) <= 1, "Two local-memory requests accepted"
        if accepted:
            assert pending is None, "Second outstanding local-memory request"
            owner = accepted[0]
            port = ("instruction", "data")[owner]
            assert positions[owner] < len(queues[owner]), "Extra local-memory request"
            item = queues[owner][positions[owner]]
            assert item["phase"] == sample["phase"], "Wrong initialization or verification phase"
            assert tuple(sample[f"{port}_request_{field}"] for field in REQUEST) == tuple(item[field] for field in REQUEST), "Changed local-memory request"
            if all(sample[f"{p}_request_valid"] for p in ("instruction", "data")):
                assert owner == prefer, "Local-memory arbitration did not alternate"
                counts["contendedGrants"] += 1
            prefer = 1 - owner
            positions[owner] += 1
            allowed = legal(parameters, owner, item)
            value = 0
            address = item["address"] & ~3
            if allowed:
                if item["write"]:
                    for lane in range(4):
                        if item["mask"] & (1 << lane):
                            memory[address + lane] = (item["data"] >> (8 * lane)) & 255
                    counts["writes"] += 1
                    counts[f"writeMask{item['mask']}"] += 1
                    counts[f"writeSize{item['size']}"] += 1
                else:
                    assert all(address + lane in memory for lane in range(4)), "Test read before byte initialization"
                    value = sum(memory[address + lane] << (8 * lane) for lane in range(4))
                    counts["reads"] += 1
                    if sample["phase"] == 2:
                        readback.add(address)
            else:
                counts["rejected"] += 1
                counts["rejectedWrites"] += bool(item["write"])
                counts["rejectedAtomic"] += bool(item["operation"])
            latency = parameters["readLatency"] if allowed and not item["write"] else 1
            pending = {"owner": owner, "data": value, "fault": int(not allowed), "due": cycle + latency}
            counts["requests"] += 1
            if old:
                assert finished, "Replacement without completion"
                counts["replacements"] += 1
                counts["sameOwnerReplacements" if old["owner"] == owner else "otherOwnerReplacements"] += 1
        previous = sample
    if complete:
        assert pending is None and positions == [len(q) for q in queues], "Incomplete local-memory history"
        assert counts["responses"] == len(requests), "Missing local-memory completion"
        assert len(readback) == parameters["sizeBytes"] // 4, "Incomplete final memory readback"
    return {**counts, "finalReadbackWords": len(readback)}


def negative_controls(parameters, rows, samples):
    controls = []
    for name, kind in (("wrong-owner", "owner"), ("corrupt-read", "read"), ("lost-fault", "fault")):
        index = next(i for i, s in enumerate(samples) if any(s[f"{p}_response_valid"] and
                     (kind == "owner" or bool(s[f"{p}_response_fault"]) == (kind == "fault") and s["phase"] > 0)
                     for p in ("instruction", "data")))
        bad = list(samples[:index + 1])
        bad[-1] = dict(bad[-1])
        port = "instruction" if bad[-1]["instruction_response_valid"] else "data"
        if kind == "owner":
            bad[-1][f"{port}_response_valid"] = 0
            bad[-1][f"{'data' if port == 'instruction' else 'instruction'}_response_valid"] = 1
        elif kind == "fault":
            bad[-1][f"{port}_response_fault"] = 0
        else:
            bad[-1][f"{port}_response_data"] ^= 1
        try:
            check(parameters, rows, bad, complete=False)
        except AssertionError as error:
            expected = "Wrong response owner or latency" if kind == "owner" else "Wrong local-memory response"
            assert expected in str(error), f"Wrong {name} negative-control failure: {error}"
            controls.append(name)
        else:
            raise AssertionError(f"Accepted {name} negative control")
    return controls


def wrapper():
    text = """// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2
import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
class LocalMemoryTestIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val bank = Flipped(UInt(3))
  val instruction = Flipped(new MemoryPort)
  val data = Flipped(new MemoryPort)
@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, LocalMemoryTestIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2LocalMemoryBench"
  def architecture(p: Parameters) =
    val io = summon[Interface[LocalMemoryTestIO]]
    io.instruction.request.ready := false.B
    io.data.request.ready := false.B
    io.instruction.response.valid := false.B
    io.data.response.valid := false.B
    io.instruction.response.bits.data := 0.U(32)
    io.instruction.response.bits.fault := false.B
    io.data.response.bits :<= io.instruction.response.bits
"""
    for index, p in enumerate(CASES):
        text += f"""    val bank{index} = LocalMemory.instantiate(LocalMemoryParameters({p['baseAddress']}L, {p['sizeBytes']}, {p['readLatency']}))
    bank{index}.io.clock := io.clock
    bank{index}.io.reset := io.reset
"""
        for port in ("instruction", "data"):
            text += f"""    bank{index}.io.{port}.request.valid := (io.bank === {index}.U(3)) & io.{port}.request.valid
    bank{index}.io.{port}.request.bits :<= io.{port}.request.bits
    bank{index}.io.{port}.response.ready := (io.bank === {index}.U(3)) & io.{port}.response.ready
    when(io.bank === {index}.U(3)) {{
      io.{port}.request.ready := bank{index}.io.{port}.request.ready
      io.{port}.response.valid := bank{index}.io.{port}.response.valid
      io.{port}.response.bits :<= bank{index}.io.{port}.response.bits
    }}
"""
    return text


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("result/local-memory"))
    args = parser.parse_args()
    output = args.output.resolve()
    assert not output.exists() or not any(output.iterdir()), "Local-memory output must be empty"
    output.mkdir(parents=True, exist_ok=True)
    names = ["ditdah_e2/src/" + n for n in ("Parameters.scala", "Interfaces.scala", "DebugTransportInterfaces.scala",
              "SramInterfaces.scala", "Sram.scala", "Sram.sv", "LocalMemoryInterfaces.scala", "LocalMemory.scala")]
    names += ["test/units/local_memory.py", "test/test_local_memory/local_memory_sim.cpp", "test/test_local_memory/test_local_memory.py", "flake.nix", "flake.lock"]
    names += [str(p.relative_to(ROOT)) for p in sorted((ROOT / "nix").glob("*.nix"))]
    originals = {n: (ROOT / n).read_bytes() for n in names}
    for n, data in originals.items():
        p = output / "inputs" / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    commands = []
    tool_paths = {name: Path(shutil.which(name)).resolve() for name in
                  ("elaborate-ditdah-e2", "firld", "firtool", "verilator", "c++")}
    tool_hashes = {name: digest(path) for name, path in tool_paths.items()}
    versions = {name: subprocess.check_output(command, text=True).strip() for name, command in
                (("firld", ["firld", "--version"]), ("firtool", ["firtool", "--version"]),
                 ("verilator", ["verilator", "--version"]), ("c++", ["c++", "--version"]))}
    versions["c++"] = versions["c++"].splitlines()[0]
    report = {"scope": "two-owner local SRAM transaction and byte-memory history", "cases": list(CASES),
              "inputHashes": {n: hashlib.sha256(b).hexdigest() for n, b in originals.items()},
              "toolHashes": tool_hashes, "tools": versions, "runs": [], "exitStatus": None}
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-local-memory-", dir="/data/tmp" if os.access("/data/tmp", os.W_OK) else None) as directory:
        work = Path(directory)
        (work / "src").mkdir()
        for n, data in originals.items():
            if n.endswith(".scala"):
                (work / "src" / Path(n).name).write_bytes(data)
        (work / "src/Top.scala").write_text(wrapper())
        (output / "wrapper.scala").write_text(wrapper())
        (work / "parameters.json").write_text('{"resetVector":0}\n')
        env = dict(os.environ, DITDAH_E2_SOURCE=str(work / "src"))
        def run(command, label):
            result = subprocess.run(command, cwd=work, env=env, capture_output=True, text=True)
            (output / (label + ".log")).write_text((result.stdout + result.stderr).replace(str(work), "<work>").replace(str(output), "<evidence>"))
            commands.append({"argv": [s.replace(str(work), "<work>").replace(str(output), "<evidence>") for s in command], "exitStatus": result.returncode})
            assert result.returncode == 0, f"Local-memory {label} failed"
            return result.stdout
        run(["elaborate-ditdah-e2", "design", "parameters.json"], "elaborate")
        run(["firld", *[p.name for p in sorted(work.glob("*.mlirbc"))], "--base-circuit", TOP,
             "--no-mangle", "--emit-bytecode", "-o", "linked.mlirbc"], "link")
        run(["firtool", "linked.mlirbc", "--split-verilog", "-disable-all-randomization",
             "--lowering-options=noAlwaysComb,disallowLocalVariables,locationInfoStyle=none", "-o", "rtl"], "lower")
        (work / "rtl/Sram.sv").write_bytes(originals["ditdah_e2/src/Sram.sv"])
        shutil.copytree(work / "rtl", output / "rtl")
        run(["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", TOP, "-Wno-fatal",
             *[str(p) for p in sorted((work / "rtl").glob("*.sv"))], str(output / "inputs/test/test_local_memory/local_memory_sim.cpp")], "build")
        for bank, p in enumerate(CASES):
            rows = vectors(p)
            text = "".join(" ".join(str(x[k]) for k in ("phase", "owner", *REQUEST)) + "\n" for x in rows)
            (work / "vectors.txt").write_text(text)
            for delayed in (0, 1):
                label = f"{p['name']}-stalls-{delayed}"
                trace = run([str(work / "obj_dir" / ("V" + TOP)), "vectors.txt", str(bank), str(delayed)], label)
                samples = list(parse_trace(trace.splitlines()))
                metrics = check(p, rows, samples)
                controls = negative_controls(p, rows, samples)
                assert metrics["resetCycles"] == 6 and metrics["rejectedAtomic"] == 45, "Missing reset or atomic rejection coverage"
                assert all(metrics.get(k, 0) for k in ("replacements", "sameOwnerReplacements", "otherOwnerReplacements", "contendedGrants", "rejectedWrites")), "Missing controller coverage"
                assert all(metrics.get(f"writeMask{mask}", 0) for mask in (1, 2, 4, 8, 3, 12, 15)), "Missing byte-lane mask coverage"
                assert all(metrics.get(f"writeSize{size}", 0) for size in range(3)), "Missing byte, halfword or word writes"
                if delayed:
                    assert metrics.get("responseStalls", 0), "Missing response backpressure"
                with gzip.GzipFile(filename="", mode="wb", fileobj=(output / (label + ".trace.gz")).open("wb"), mtime=0) as f:
                    f.write(trace.encode())
                report["runs"].append({"case": p, "delayed": bool(delayed), "metrics": metrics, "negativeControls": controls,
                                       "vectorSha256": hashlib.sha256(text.encode()).hexdigest(), "traceSha256": hashlib.sha256(trace.encode()).hexdigest()})
                print(label, metrics["responses"], "responses", flush=True)
        report.update({"commands": commands, "rtlHashes": {p.name: digest(p) for p in (output / "rtl").glob("*.sv")},
                       "wrapperHash": hashlib.sha256(wrapper().encode()).hexdigest(), "exitStatus": 0,
                       "assumptions": ["quiescent cold reset", "one accepted outstanding transaction globally", "written-byte initialization before reads"],
                       "excluded": ["CPU integration", "SRAM macro mapping", "PMP", "atomic implementation", "warm reset"]})
    assert all((ROOT / n).read_bytes() == b for n, b in originals.items()), "Local-memory inputs changed during verification"
    assert all(digest(path) == tool_hashes[name] for name, path in tool_paths.items()), "Local-memory tools changed during verification"
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: local-memory ownership, latency, masks and full memory readback")


if __name__ == "__main__":
    main()
