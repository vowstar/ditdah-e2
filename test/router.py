# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check generated memory router RTL against an independent transaction model."""

import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TOP = "DitDahE2MemoryRouter"
PORTS = ("instruction", "data", "memoryInstruction", "memoryData", "console", "timer")
REQUEST = ("address", "write", "data", "mask", "size")
RESPONSE = ("data", "fault")
FIELDS = ("cycle", "reset") + tuple(
    f"{port}_{channel}_{field}"
    for port in PORTS for channel, payload in (("request", REQUEST), ("response", RESPONSE))
    for field in ("valid", "ready", *payload))


def route(regions, owner, request):
    address, write, _, mask, size = (request[key] for key in REQUEST)
    if size not in (0, 1, 2):
        return None
    width = 1 << size
    if address % width or mask != (((1 << width) - 1) << (address % 4) if write else 0):
        return None
    region = next((name for name, item in regions.items()
                   if item["base"] <= address < item["base"] + item["size"]), None)
    if owner == 0:
        return ("memoryInstruction", address) if region in ("rom", "sram") and not write and width == 4 else None
    if region == "sram" or region == "rom" and not write:
        return "memoryData", address
    if region in ("console", "timer") and width == 4:
        return region, address - regions[region]["base"]
    return None


def vectors(regions, seed, count=1024):
    rng = random.Random(seed)
    rows = []
    for owner in (0, 1):
        for region in regions.values():
            for lane in range(4):
                for size in range(4):
                    for write in range(2):
                        for mask in range(16):
                            rows.append(dict(owner=owner, address=region["base"] + lane,
                                             write=write, data=rng.getrandbits(32), mask=mask, size=size))
            for offset in (-4, 0, region["size"] - 4, region["size"]):
                for write in range(2):
                    rows.append(dict(owner=owner, address=(region["base"] + offset) & 0xFFFFFFFF,
                                     write=write, data=rng.getrandbits(32), mask=15 if write else 0, size=2))
        for index in range(count):
            region = rng.choice(tuple(regions.values()))
            address = ((region["base"] + rng.randrange(region["size"])) if index % 5 else rng.getrandbits(32))
            size, write = rng.randrange(4), rng.randrange(2)
            mask = rng.randrange(16)
            if index % 3:
                size = rng.randrange(3)
                address &= ~((1 << size) - 1)
                mask = ((1 << (1 << size)) - 1) << (address % 4) if write else 0
            rows.append(dict(owner=owner, address=address, write=write, data=rng.getrandbits(32), mask=mask, size=size))
    return rows


def negative_vectors(regions):
    rows = []
    for owner in (0, 1):
        for name, write, mask in (("sram", 0, 0), ("sram", 0, 0), ("rom", 1, 0),
                                  ("console", 0, 0), ("timer", 0, 0), ("sram", 1, 15)):
            rows.append(dict(owner=owner, address=regions[name]["base"], write=write,
                             data=0x12345678, mask=mask, size=2))
    return rows


def parse_trace(lines):
    iterator = iter(lines)
    assert next(iterator).split() == list(FIELDS), "Unexpected trace fields"
    for cycle, line in enumerate(iterator):
        values = list(map(int, line.split()))
        assert len(values) == len(FIELDS), f"Incomplete trace at cycle {cycle}"
        sample = dict(zip(FIELDS, values, strict=True))
        assert sample["cycle"] == cycle, "Missing trace cycle"
        yield sample


def check(regions, requests, samples, complete=True):
    queues = [[item for item in requests if item["owner"] == owner] for owner in (0, 1)]
    positions = [0, 0]
    owners = [None, None]
    previous = None
    counts = Counter()

    def value(sample, port, channel, field):
        return sample[f"{port}_{channel}_{field}"]

    def payload(sample, port, channel, fields):
        return tuple(value(sample, port, channel, field) for field in fields)

    def transfer(sample, port, channel):
        return value(sample, port, channel, "valid") and value(sample, port, channel, "ready")

    for sample in samples:
        cycle = sample["cycle"]
        counts["cycles"] += 1
        if sample["reset"]:
            assert cycle < 2 and not any(owners), "Reset during a transaction"
            assert not any(value(sample, port, "request", "valid") for port in PORTS), "Request during reset"
            previous = None
            continue
        if previous:
            for port in PORTS:
                for channel, fields in (("request", REQUEST), ("response", RESPONSE)):
                    if value(previous, port, channel, "valid") and not value(previous, port, channel, "ready"):
                        assert value(sample, port, channel, "valid"), f"Withdrawn {port} {channel} at cycle {cycle}"
                        assert payload(sample, port, channel, fields) == payload(previous, port, channel, fields), (
                            f"Unstable {port} {channel} at cycle {cycle}")
        finished = [False, False]
        for owner, port in enumerate(PORTS[:2]):
            active = owners[owner]
            response_valid = value(sample, port, "response", "valid")
            if active is None:
                assert not response_valid, f"Unowned {port} response at cycle {cycle}"
                continue
            assert cycle > active["cycle"], "Response on its request acceptance edge"
            endpoint = active["route"][0] if active["route"] else None
            expected_valid = value(sample, endpoint, "response", "valid") if endpoint else 1
            assert response_valid == expected_valid, f"Wrong {port} response valid at cycle {cycle}"
            if response_valid:
                expected = payload(sample, endpoint, "response", RESPONSE) if endpoint else (0, 1)
                assert payload(sample, port, "response", RESPONSE) == expected, f"Wrong {port} response payload at cycle {cycle}"
                if transfer(sample, port, "response"):
                    finished[owner] = True
                    counts["responses"] += 1
                    counts[f"owner{owner}Responses"] += 1
                    counts["faultResponses" if expected[1] else "successfulResponses"] += 1
                else:
                    counts["responseStalls"] += 1
            if value(sample, port, "request", "valid"):
                counts["nextOffersWhileActive"] += 1
            assert not transfer(sample, port, "request") or finished[owner], "Second outstanding request"
        for endpoint in PORTS[2:]:
            active_owner = next((owner for owner, active in enumerate(owners)
                                 if active and active["route"] and active["route"][0] == endpoint), None)
            if active_owner is None:
                assert not value(sample, endpoint, "response", "valid"), f"Unowned endpoint response from {endpoint}"
                assert not value(sample, endpoint, "response", "ready"), f"Unowned response ready for {endpoint}"
            else:
                assert value(sample, endpoint, "response", "ready") == value(
                    sample, PORTS[active_owner], "response", "ready"), "Wrong endpoint response ready"
                if transfer(sample, endpoint, "response"):
                    counts["endpointResponses"] += 1
        accepted = [None, None]
        expected_endpoints = {}
        for owner, port in enumerate(PORTS[:2]):
            if not value(sample, port, "request", "valid"):
                continue
            assert positions[owner] < len(queues[owner]), "Extra upstream request"
            request = queues[owner][positions[owner]]
            assert payload(sample, port, "request", REQUEST) == tuple(request[key] for key in REQUEST), "Changed upstream request"
            destination = route(regions, owner, request)
            if destination:
                endpoint, address = destination
                expected_endpoints[endpoint] = owner, (address, *(request[key] for key in REQUEST[1:]))
            if transfer(sample, port, "request"):
                assert owners[owner] is None or finished[owner], "Second outstanding request"
                accepted[owner] = {"route": destination, "cycle": cycle}
                positions[owner] += 1
                counts["requests"] += 1
                counts[f"owner{owner}Requests"] += 1
                counts["rejected" if destination is None else destination[0] + "Requests"] += 1
                counts["writeRequests" if request["write"] else "readRequests"] += 1
        for endpoint in PORTS[2:]:
            valid = value(sample, endpoint, "request", "valid")
            expected = expected_endpoints.get(endpoint)
            if valid:
                assert expected is not None, f"Wrong endpoint offer to {endpoint} at cycle {cycle}"
                owner, expected_payload = expected
                assert payload(sample, endpoint, "request", REQUEST) == expected_payload, f"Wrong endpoint payload for {endpoint}"
                if not value(sample, endpoint, "request", "ready"):
                    counts["endpointRequestStalls"] += 1
            fired = transfer(sample, endpoint, "request")
            if fired:
                owner = expected[0]
                assert owners[owner] is None or finished[owner], f"Repeated endpoint acceptance for {endpoint} at cycle {cycle}"
            expected_fire = any(item and item["route"] and item["route"][0] == endpoint for item in accepted)
            assert bool(fired) == expected_fire, f"Endpoint acceptance differs for {endpoint} at cycle {cycle}"
            if fired:
                counts["endpointRequests"] += 1
        if all(item is not None for item in owners):
            counts["concurrentOwners"] += 1
        for owner in (0, 1):
            if finished[owner]:
                owners[owner] = None
            if accepted[owner]:
                owners[owner] = accepted[owner]
        previous = sample
    if complete:
        assert not any(owners), "Unfinished upstream request"
        assert positions == list(map(len, queues)), "Unaccepted test requests"
        assert counts["responses"] == len(requests), "Missing upstream completion"
        assert counts["endpointRequests"] == counts["endpointResponses"], "Unfinished endpoint request"
    return dict(counts)


def harness():
    def io(port, channel, field):
        return f"dut.{port}_{channel}_{'bits_' if field not in ('valid', 'ready') else ''}{field}"

    body = '''// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#include "VDitDahE2MemoryRouter.h"
#include <array>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
struct Request { uint32_t address, write, data, mask, size; };
struct Response { uint32_t due, data, fault; };
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    std::ifstream input(argv[1]);
    unsigned seed = std::stoul(argv[2]), mode = std::stoul(argv[3]), owner;
    std::array<std::vector<Request>, 2> requests;
    Request item;
    while (input >> owner >> item.address >> item.write >> item.data >> item.mask >> item.size)
        requests.at(owner).push_back(item);
    VDitDahE2MemoryRouter dut;
    std::array<unsigned, 2> position{}, completed{};
    std::array<bool, 2> offered{};
    std::array<std::deque<Response>, 4> responses;
    std::array<unsigned, 4> sequence{};
    auto random = [&]() { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; return seed; };
    unsigned drained = 0;
    std::cout << "@HEADER@\\n";
    for (unsigned cycle = 0; cycle < 100 + 100 * (requests[0].size() + requests[1].size()); ++cycle) {
        dut.clock = 0;
        dut.reset = cycle < 2;
'''.replace("@HEADER@", " ".join(FIELDS))
    for owner, port in enumerate(PORTS[:2]):
        body += f'''        if (!dut.reset && !offered[{owner}] && position[{owner}] < requests[{owner}].size()
            && (!mode || random() % 4)) offered[{owner}] = true;
        {io(port, 'request', 'valid')} = offered[{owner}];
        {io(port, 'response', 'ready')} = !dut.reset && (!mode || ((cycle + {owner} * 11) % 41 >= 17 && random() % 4));
        if (offered[{owner}]) {{
            const auto &request = requests[{owner}][position[{owner}]];
'''
        body += "".join(f"            {io(port, 'request', field)} = request.{field};\n" for field in REQUEST)
        body += "        }\n"
    for index, port in enumerate(PORTS[2:]):
        body += f'''        {io(port, 'request', 'ready')} = !dut.reset && (!mode || ((cycle + {index} * 7) % 29 >= 8 && random() % 3));
        {io(port, 'response', 'valid')} = !responses[{index}].empty() && cycle >= responses[{index}].front().due;
        {io(port, 'response', 'data')} = responses[{index}].empty() ? random() : responses[{index}].front().data;
        {io(port, 'response', 'fault')} = responses[{index}].empty() ? random() % 2 : responses[{index}].front().fault;
'''
    body += "        dut.eval();\n        std::cout << cycle << ' ' << unsigned(dut.reset)"
    for port in PORTS:
        for channel, fields in (("request", REQUEST), ("response", RESPONSE)):
            for field in ("valid", "ready", *fields):
                body += f"\n            << ' ' << uint32_t({io(port, channel, field)})"
    body += " << '\\n';\n        if (!dut.reset) {\n"
    for index, port in enumerate(PORTS[2:]):
        body += f'''            if ({io(port, 'response', 'valid')} && {io(port, 'response', 'ready')}) responses[{index}].pop_front();
            if ({io(port, 'request', 'valid')} && {io(port, 'request', 'ready')}) {{
                unsigned serial = ++sequence[{index}];
                responses[{index}].push_back({{cycle + 1 + (mode ? random() % 13 : 0),
                    uint32_t(0x10000000u * ({index} + 1) + serial), uint32_t(serial % 7 == 0)}});
            }}
'''
    for owner, port in enumerate(PORTS[:2]):
        body += f'''            if ({io(port, 'request', 'valid')} && {io(port, 'request', 'ready')}) {{
                ++position[{owner}]; offered[{owner}] = false;
            }}
            if ({io(port, 'response', 'valid')} && {io(port, 'response', 'ready')}) ++completed[{owner}];
'''
    body += '''        }
        dut.clock = 1;
        dut.eval();
        bool done = true;
        for (unsigned index = 0; index < 2; ++index)
            done &= position[index] == requests[index].size() && completed[index] == requests[index].size();
        for (const auto &queue : responses) done &= queue.empty();
        drained = done ? drained + 1 : 0;
        if (drained == 8) return 0;
    }
    return 3;
}
'''
    return body


def mutate(text, name):
    patterns = {
        "direction": (r"& ~instruction_request_bits_write", "& 1'h1"),
        "duplicate": (r"assign memoryData_request_valid = ~dataActive & data_request_valid & memory;",
                      "assign memoryData_request_valid = data_request_valid & memory;"),
        "endpoint": (r"assign timer_request_valid = ~dataActive & data_request_valid & timer_0;",
                     "assign timer_request_valid = ~dataActive & data_request_valid & console;"),
    }
    pattern, replacement = patterns[name]
    result, count = re.subn(pattern, replacement, text)
    assert count == 1, f"{name} mutation no longer matches generated RTL"
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_hashes(base, hashes):
    for name, expected in hashes.items():
        assert digest(base / name) == expected, f"Changed frozen input: {name}"


def freeze(build, output):
    manifest = json.loads((build / "manifest.json").read_text())
    assert manifest["exitStatus"] == 0, "Platform generation did not pass"
    for prefix, group in (("inputs", "sourceHashes"), ("inputs/generated", "generatedHashes"),
                          ("rtl", "rtlHashes"), ("", "artifactHashes")):
        verify_hashes(build / prefix, manifest[group])
    assert digest(build / "inputs/platform.json") == manifest["platformHash"], "Changed platform map"
    assert json.loads((build / "map.json").read_text()) == manifest["regions"], "Map differs from generation manifest"
    assert json.loads((build / "parameters.json").read_text()) == manifest["parameters"], "Configuration differs from generation manifest"
    archive = output / "inputs"
    shutil.copytree(build / "inputs", archive / "platform/inputs")
    shutil.copytree(build / "rtl", archive / "platform/rtl")
    for name in ("manifest.json", *manifest["artifactHashes"]):
        shutil.copyfile(build / name, archive / "platform" / name)
    for name in ("router.py", "test_router.py"):
        target = archive / "test" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(__file__).with_name(name), target)
    (archive / "router_sim.cpp").write_text(harness())
    return manifest, archive, {str(path.relative_to(archive)): digest(path)
                              for path in sorted(archive.rglob("*")) if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-build", type=Path, default=ROOT / "result/platform-rtl")
    parser.add_argument("--output", type=Path, default=ROOT / "result/router")
    args = parser.parse_args()
    output = args.output.resolve()
    assert not output.exists() or not any(output.iterdir()), "Router output directory must be empty"
    output.mkdir(parents=True, exist_ok=True)
    manifest, archive, hashes = freeze(args.platform_build.resolve(), output)
    tool_paths = {name: Path(shutil.which(name)).resolve() for name in ("verilator", "verilator_bin", "c++")}
    tools = {name: digest(path) for name, path in tool_paths.items()}
    report = {"scope": "standalone generated router simulation", "parameters": manifest["parameters"],
              "regions": manifest["regions"], "inputs": hashes, "tools": tools,
              "verilator": subprocess.check_output(["verilator", "--version"], text=True).strip(),
              "compiler": subprocess.check_output(["c++", "--version"], text=True).splitlines()[0],
              "runs": [], "negativeControls": [], "exitStatus": None}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    scratch = "/data/tmp" if os.access("/data/tmp", os.W_OK) else None
    with tempfile.TemporaryDirectory(prefix="ditdah-e2-router-", dir=scratch) as directory:
        work = Path(directory)
        rtl = (archive / "platform/rtl" / f"{TOP}.sv").read_text()
        for variant in ("positive", "direction", "duplicate", "endpoint"):
            case = output / variant
            case.mkdir()
            source = case / f"{TOP}.sv"
            source.write_text(rtl if variant == "positive" else mutate(rtl, variant))
            rtl_hash = digest(source)
            object_dir = work / variant
            command = ["verilator", "--cc", "--exe", "--build", "-j", "2", "--top-module", TOP,
                       "--Mdir", str(object_dir), "-CFLAGS", "-std=c++17", str(source), str(archive / "router_sim.cpp")]
            compiled = subprocess.run(command, capture_output=True, text=True)
            (case / "build.log").write_text((compiled.stdout + compiled.stderr).replace(str(work), "<work>").replace(str(output), "<evidence>"))
            assert compiled.returncode == 0, f"Router {variant} compilation failed"
            build_record = {"command": [part.replace(str(work), "<work>").replace(str(output), "<evidence>") for part in command],
                            "exitStatus": compiled.returncode, "logHash": digest(case / "build.log"),
                            "binaryHash": digest(object_dir / ("V" + TOP))}
            (case / "build.json").write_text(json.dumps(build_record, indent=2) + "\n")
            cases = ((19, 0), (29, 1), (37, 1)) if variant == "positive" else ((29, 1),)
            for seed, mode in cases:
                rows = vectors(manifest["regions"], seed) if variant == "positive" else negative_vectors(manifest["regions"])
                vector_path = case / f"vectors-{seed}.txt"
                vector_path.write_text("".join(" ".join(str(row[key]) for key in ("owner", *REQUEST)) + "\n" for row in rows))
                vector_hash = digest(vector_path)
                trace = work / "trace.txt"
                with trace.open("w") as stream:
                    run = subprocess.run([str(object_dir / ("V" + TOP)), str(vector_path), str(seed), str(mode)],
                                         stdout=stream, stderr=subprocess.PIPE, text=True)
                error = None
                metrics = None
                try:
                    with trace.open() as stream:
                        metrics = check(manifest["regions"], rows, parse_trace(stream), complete=variant == "positive")
                except AssertionError as caught:
                    error = str(caught)
                trace_path = case / f"trace-{seed}.txt.gz"
                with trace.open("rb") as source_stream, trace_path.open("wb") as destination:
                    with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
                        shutil.copyfileobj(source_stream, compressed)
                assert digest(source) == rtl_hash and digest(vector_path) == vector_hash, "Run inputs changed"
                assert digest(object_dir / ("V" + TOP)) == build_record["binaryHash"], "Simulator changed"
                item = {"seed": seed, "delayed": bool(mode), "rtlHash": rtl_hash, "vectorHash": vector_hash,
                        "traceHash": digest(trace_path), "rtlExitStatus": run.returncode, "checkerError": error,
                        "metrics": metrics, "buildHash": digest(case / "build.json"),
                        "command": ["<build>/V" + TOP, vector_path.name, str(seed), str(mode)]}
                if variant == "positive":
                    assert run.returncode == 0, "Router simulation did not complete"
                    assert error is None, error
                    if mode:
                        assert all(metrics.get(key, 0) for key in ("concurrentOwners", "endpointRequestStalls", "responseStalls",
                                                                  "nextOffersWhileActive", "memoryInstructionRequests",
                                                                  "memoryDataRequests", "consoleRequests", "timerRequests")), "Missing router coverage"
                    report["runs"].append(item)
                else:
                    expected = {"direction": "Wrong endpoint offer", "duplicate": "Repeated endpoint acceptance",
                                "endpoint": "Wrong endpoint offer"}[variant]
                    assert error and expected in error, f"Ineffective {variant} mutation: {error}"
                    report["negativeControls"].append({"name": variant, **item})
                (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
                print(f"Router {variant} seed {seed}: " + (error if error else f"{metrics['responses']} checked responses"), flush=True)
    verify_hashes(archive, hashes)
    assert all(digest(path) == tools[name] for name, path in tool_paths.items()), "Verification tools changed"
    report["exitStatus"] = 0
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
