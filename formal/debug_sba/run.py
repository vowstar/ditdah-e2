# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Freeze and validate commercial SBA and memory-arbiter protocol cases."""

import argparse
import hashlib
import importlib.util
import json
import math
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = "ditdah-e2.debug-sba-commercial.v1"
RESET_ADAPTER = "ditdah-e2.commercial-reset-input.v1"
RESET_PROLOGS = {
    "debug_sba_formal": b"module debug_sba_formal(input clock);\n"
                        b"  reg reset = 1;\n"
                        b"  reg past_valid = 0;\n"
                        b"  always @(posedge clock) begin reset <= 0; past_valid <= 1; end\n",
    "arbiter_formal": b"module arbiter_formal(input clock);\n"
                      b"  reg reset = 1, past_valid = 0;\n"
                      b"  always @(posedge clock) begin reset <= 0; past_valid <= 1; end\n",
}
RAW = ("validity_status", "run_status", "engine", "min_length", "max_length",
       "target_bound", "trace_length", "latest_trace_engine")
ASSUMPTION_PROOF_FIELDS = ("engine", "min_length", "max_length", "trace_length", "latest_trace_engine")
META = ("native_id", "name", "type", "command", "disabled", "expression",
        "precondition", "clock", "edge")
ENGINES = {"PRE", "N", "C", "I", "Mp", "Hp"}
RESET = ("expression reset file_type {} sequence {} file_name {} hier_path {} "
         "time {} start_time {} end_time {} time_scale {} non_resettable_regs {} "
         "formal false bound 0 max_iterations {} none false reset_declared true")
SPECS = {'sba': {'module': 'DitDahE2DebugSystemBus', 'top': 'debug_sba_formal', 'wrapper': 'debug_sba_formal.sv', 'assertions': ('sba_response_owner', 'sba_single_outstanding', 'sba_idle_quiet', 'sba_owned_not_idle', 'sba_stalled_offer_valid', 'sba_stalled_payload_stable', 'sba_machine_access', 'sba_ordinary_access', 'sba_supported_size', 'sba_halfword_alignment', 'sba_word_alignment', 'sba_write_mask', 'sba_inactive_hidden', 'sba_version', 'sba_reserved_bits', 'sba_busy_status', 'sba_address_width', 'sba_access_capabilities'), 'assumptions': ('memory_response_owned', 'memory_response_valid_stable', 'memory_response_data_stable', 'memory_response_fault_stable'), 'covers': ('cover_byte_lane3', 'cover_halfword_lane2', 'cover_word_read', 'cover_deactivated_offer', 'cover_cancelled_return_new_epoch', 'cover_busy_conflict', 'cover_bus_fault', 'cover_alignment_error', 'cover_unsupported_size'), 'negativeTarget': 'sba_write_mask', 'mutationPort': 'systemBus_request_bits_mask', 'mutationValue': "4'h0"}, 'arbiter': {'module': 'DitDahE2MemoryArbiter', 'top': 'arbiter_formal', 'wrapper': 'arbiter_formal.sv', 'assertions': ('arbiter_single_source_accept', 'arbiter_exact_request_accept', 'arbiter_single_pending', 'arbiter_offer_policy', 'arbiter_payload_owner', 'arbiter_offer_tag', 'arbiter_stalled_offer_valid', 'arbiter_stalled_payload_tag', 'arbiter_first_response_owner', 'arbiter_second_response_owner', 'arbiter_response_ready_owner', 'arbiter_held_owner_tag', 'arbiter_first_response_data', 'arbiter_first_response_fault', 'arbiter_second_response_data', 'arbiter_second_response_fault'), 'assumptions': ('bus_response_owned', 'first_source_valid_stable', 'first_source_payload_stable', 'second_source_valid_stable', 'second_source_payload_stable', 'bus_response_valid_stable', 'bus_response_data_stable', 'bus_response_fault_stable'), 'covers': ('cover_first_contention_grant', 'cover_second_contention_grant', 'cover_stalled_debug_change', 'cover_first_response_stall', 'cover_second_response_stall', 'cover_first_fault', 'cover_second_fault', 'cover_round_robin_second'), 'negativeTarget': 'arbiter_first_response_owner', 'mutationPort': 'first_response_valid', 'mutationValue': 'output_response_valid'}}

COLLECTOR = r'''# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
source [file join [file dirname [info script]] plan.tcl]
set records [open native.tsv w]
proc sba_record {tag key value} {
    global records
    set row {}
    foreach field [list $tag $key $value] {lappend row [binary encode hex [encoding convertto utf-8 $field]]}
    puts $records [join $row "\t"]
    flush $records
}
proc sba_canonical {name} {return [regsub {^<embedded>::} $name {}]}
proc sba_property {label} {
    global top source_assumptions
    set found {}
    set ids [list "${top}.${label}"]
    if {$label in $source_assumptions} {lappend ids "::${top}.${label}"} else {lappend ids "<embedded>::${top}.${label}"}
    foreach item [get_property_list] {
        if {$item in $ids} {lappend found $item}
    }
    if {[llength $found] != 1} {
        sba_record run lookup_label $label
        foreach item [get_property_list] {
            array unset info;array set info [get_property_info $item]
            sba_record lookup.$label $item [list $info(name) $info(type)]
        }
        error "missing or ambiguous exact property"
    }
    return [lindex $found 0]
}
proc sba_inventory {tag} {
    global top all_assertions source_assumptions declared_covers source_labels
    set aa {};set ee {};set cc {}
    foreach item [get_property_list] {
        array unset info;array set info [get_property_info $item]
        set name [sba_canonical $info(name)]
        if {$info(disabled)} {error "disabled source property"}
        switch -- $info(type) {
            assert {lappend aa $name}
            assume {lappend ee $name}
            cover {lappend cc $name}
            default {error "unknown native property type"}
        }
    }
    foreach {key values} [list native_assertions $aa native_assumptions $ee native_covers $cc] {
        sba_record $tag $key [lsort $values]
        if {[llength $values] != [llength [lsort -unique $values]]} {error "duplicate native identity"}
    }
    set want {};foreach label $all_assertions {lappend want "${top}.${label}"}
    if {[lsort $aa] ne [lsort $want]} {error "assertion inventory differs"}
    set want {};foreach label $source_assumptions {lappend want "${top}.${label}"}
    if {[lsort $ee] ne [lsort $want]} {error "assumption inventory differs"}
    set want {};foreach label $declared_covers {lappend want "${top}.${label}"}
    foreach item $want {if {$item ni $cc} {error "declared cover is missing"}}
    foreach item $cc {
        if {$item in $want} {continue}
        set prefix "${top}."
        if {[string first $prefix $item] != 0} {error "foreign native cover"}
        set leaf [string range $item [string length $prefix] end]
        if {![regexp {^([A-Za-z_][A-Za-z0-9_]*):precondition[1-9][0-9]*$} $leaf -> owner] || $owner ni $source_labels} {
            error "unexpected native cover"
        }
    }
}
proc sba_metadata {tag label} {
    set item [sba_property $label]
    sba_record $tag native_id $item
    array set info [get_property_info $item]
    foreach key {name type command disabled expression precondition clock edge validity_status run_status engine min_length max_length target_bound trace_length latest_trace_engine} {
        sba_record $tag $key [expr {[info exists info($key)] ? $info($key) : "__missing__"}]
    }
}
proc sba_snapshot {tag} {global source_labels;foreach label $source_labels {sba_metadata "$tag.$label" $label}}
proc sba_scope {tag} {
    sba_record $tag clock [clock -list configuration -silent]
    sba_record $tag reset [reset -list -typed_list -silent]
    sba_record $tag global [assume -list -silent -env]
    sba_record $tag reset_assumptions [assume -reset -list -silent]
}
set exported {}
proc sba_export_witness {label kind} {
    global exported
    if {$label in $exported} {return}
    if {[file exists "$label.vcd"]} {error "witness destination already exists"}
    if {$kind eq "cover"} {visualize -cover -property [sba_property $label] -batch -silent} else {
        visualize -violation -property [sba_property $label] -batch -silent
    }
    visualize -save -vcd "$label.vcd"
    if {![file isfile "$label.vcd"]} {error "witness export missing"}
    lappend exported $label
}
proc sba_query {tag kind seconds engines iteration labels} {
    set items {};foreach label $labels {lappend items [sba_property $label]}
    sba_record $tag actual_properties $items
    sba_record $tag command_attempted 1
    sba_record $tag first_trace_attempt [expr {$kind eq "covers" ? "1" : "none"}]
    sba_record $tag per_property_time_limit [expr {$kind eq "covers" ? "none" : $seconds * 64}]
    sba_inventory $tag.before
    sba_snapshot $tag.before
    sba_scope $tag.before
    foreach {key value} [list labels $labels time_limit $seconds engines $engines iteration_cap $iteration per_engine_max_jobs 4 proven_facts_imported 0] {sba_record $tag $key $value}
    if {$kind eq "covers"} {
        set failed [catch {prove -property $items -engine_mode B -iter $iteration -first_trace_attempt 1 -time_limit $seconds -per_engine_max_jobs 4} message]
    } else {
        set failed [catch {prove -property $items -engine_mode {Mp N Hp} -time_limit $seconds -per_property_time_limit [expr {$seconds * 64}] -per_engine_max_jobs 4} message]
    }
    sba_snapshot $tag.after
    sba_inventory $tag.after
    sba_scope $tag.after
    if {$failed} {puts stderr $message;error "native proof command failed"}
    foreach label $labels {
        array unset info;array set info [get_property_info [sba_property $label]]
        if {$info(validity_status) eq "cex"} {sba_export_witness $label cex}
        if {$info(validity_status) eq "covered"} {sba_export_witness $label cover}
        if {$kind eq "safety" && ($info(validity_status) ne "proven" || $info(min_length) ne "infinite" || $info(target_bound) ne "0")} {error "safety did not reach native unbounded proof"}
        if {$kind eq "negative" && $info(validity_status) ne "cex"} {error "negative control is not a counterexample"}
        if {$kind eq "covers" && $info(validity_status) ne "covered"} {error "cover was not reached"}
    }
}
proc sba_execute {} {
    global sources top source_labels queries
    sba_record setup analyze_started 1
    analyze -sv12 {*}$sources
    sba_record setup elaborate_started 1
    elaborate -top $top -disable_auto_bbox -global_embedded_assumes
    foreach key {bbox_inst bbox_mod bbox_out stopat} {
        set found [get_design_info -list $key];sba_record setup $key [llength $found]
        if {[llength $found]} {error "design contains an abstraction"}
    }
    sba_record setup clock_started 1
    clock clock
    sba_record setup reset_started 1
    reset -expression reset
    sba_record setup inventory_started 1
    set identity [open executable.private w];puts $identity [info nameofexecutable];close $identity
    sba_inventory setup
    foreach label $source_labels {if {[file exists "$label.vcd"]} {error "preexisting native witness"}}
    foreach item $queries {sba_query {*}$item}
}
set failed [catch {sba_execute} message]
foreach command {"sba_snapshot final" "sba_inventory final" "sba_scope final"} {
    if {[catch {eval $command}]} {set failed 1}
}
if {$failed} {puts stderr $message;sba_record run state failed;sba_record run error native_contract_or_command_failed} else {sba_record run state complete}
close $records
exit $failed
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def backend_path():
    return HERE / "backend.py" if (HERE / "backend.py").is_file() else ROOT / "formal/debug_transport/run.py"


def backend():
    spec = importlib.util.spec_from_file_location("sba_native_backend", backend_path())
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inventories(value):
    text = value.decode()
    return {kind: re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*" + kind + r"\s*\(", text)
            for kind in ("assert", "assume", "cover")}


def check_wrapper(value, spec):
    found = inventories(value)
    for kind, field in (("assert", "assertions"), ("assume", "assumptions"), ("cover", "covers")):
        if found[kind] != list(spec[field]) or len(found[kind]) != len(set(found[kind])):
            raise ValueError("Source property inventory differs")
    text = value.decode()
    if len(re.findall(r"\b" + re.escape(spec["module"]) + r"\s+dut\s*\(", text)) != 1 or re.search(r"\bdut\s*\.", text):
        raise ValueError("Formal wrapper must bind actual DUT pins only")
    if not re.search(r"\breg\s+reset\s*=\s*1\s*[,;]", text):
        raise ValueError("Wrapper initial reset differs")


def native_wrapper(value, spec):
    """Expose only reset to the native initialization command."""
    check_wrapper(value, spec)
    prolog = RESET_PROLOGS[spec["top"]]
    header, marker, body = value.partition(b"  (* anyseq *)")
    if not marker or not header.endswith(prolog) or header.count(b"module ") != 1:
        raise ValueError("Reference reset adapter prolog differs")
    native = ("module " + spec["top"] + "(input clock, input reset);\n"
              "  reg past_valid = 0;\n"
              "  always @(posedge clock) past_valid <= 1;\n").encode()
    return header[:-len(prolog)] + native + marker + body


def wrapper_binding(value, spec):
    return {"version": RESET_ADAPTER, "reference": spec["wrapper"],
            "native": "native-" + spec["wrapper"],
            "referenceSha256": hashlib.sha256(value).hexdigest(),
            "nativeSha256": hashlib.sha256(native_wrapper(value, spec)).hexdigest()}


def mutate(value, spec):
    text = value.decode()
    changed, count = re.subn(r"(\bassign\s+" + spec["mutationPort"] + r"\s*=)[^;]+;",
                            lambda m: m[1] + " " + spec["mutationValue"] + ";", text)
    if count != 1 or changed == text:
        raise ValueError("Negative-control RTL target differs")
    return changed.encode()


def queries(plan):
    total = plan["timeLimitSeconds"]
    if plan["kind"] == "negative":
        return [("query0", "negative", total, "Mp N Hp", "none", plan["goals"])]
    safety = max(1, total * 4 // 5)
    return [("query0", "safety", safety, "Mp N Hp", "none", plan["goals"]),
            ("query1", "covers", total - safety, "B", str(plan["coverBound"]), plan["covers"])]


def plan_tcl(plan):
    fields = {"top": plan["top"], "sources": " ".join(plan["sources"]),
              "all_assertions": " ".join(plan["allAssertions"]),
              "source_assumptions": " ".join(plan["assumptions"]),
              "declared_covers": " ".join(plan["declaredCovers"]),
              "source_labels": " ".join(plan["allAssertions"] + plan["assumptions"] + plan["declaredCovers"])}
    result = "".join("set " + key + " {" + value + "}\n" for key, value in fields.items())
    rows = ["{" + tag + " " + kind + " " + str(seconds) + " {" + engines + "} " + iteration +
            " {" + " ".join(labels) + "}}" for tag, kind, seconds, engines, iteration, labels in queries(plan)]
    return (result + "set queries {\n" + "\n".join(rows) + "\n}\n").encode()


def prepare(rtl, output, arbiter_rtl=None, time_limit=300, cover_bound=64, tool_sha256=None):
    if output.exists() or type(time_limit) is not int or not 2 <= time_limit <= 300 or type(cover_bound) is not int or cover_bound < 1:
        raise ValueError("Use a new output and positive budgets")
    if tool_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", tool_sha256):
        raise ValueError("Expected tool digest is invalid")
    output.mkdir(parents=True)
    manifest = {"schema": SCHEMA, "cpuCount": 16, "timeLimitSeconds": time_limit, "coverBound": cover_bound,
                "trustedToolSha256": tool_sha256, "outerTimeoutSeconds": 360, "cases": [], "inputHashes": {}, "planHashes": {},
                "verificationHashes": {}, "buildHashes": {}, "wrapperAdapters": {}, "designs": [], "fullCoreProven": False}
    for filename, source in (("runner.py", Path(__file__)), ("backend.py", backend_path())):
        shutil.copyfile(source, output / filename)
        manifest["verificationHashes"][filename] = digest(output / filename)
    for design, directory in (("sba", rtl), ("arbiter", arbiter_rtl)):
        if directory is None:
            continue
        spec = SPECS[design]
        path = directory / (spec["module"] + ".sv") if directory.is_dir() else directory
        value = path.read_bytes()
        if value.decode().count("module " + spec["module"] + "(") != 1:
            raise ValueError("Generated module identity differs")
        wrapper = (HERE / spec["wrapper"]).read_bytes()
        native = native_wrapper(wrapper, spec)
        adapter = wrapper_binding(wrapper, spec)
        check_ports(value, design)
        build_path = directory / "manifest.json" if directory.is_dir() else directory.parent / "manifest.json"
        if build_path.exists():
            build = json.loads(build_path.read_text())
            if (build.get("top") != spec["module"] or type(build.get("exitStatus")) is not int
                    or build["exitStatus"] != 0 or build.get("rtlHashes", {}).get(path.name) != digest(path)
                    or not isinstance(build.get("sourceHashes"), dict) or not build["sourceHashes"]):
                raise ValueError("Generated RTL build manifest differs")
            for name, expected in build["sourceHashes"].items():
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts or digest(ROOT / relative) != expected:
                    raise ValueError("Generated RTL source binding differs")
            filename = "generation-" + design + ".json"
            shutil.copyfile(build_path, output / filename)
            manifest["buildHashes"][design] = digest(output / filename)
            manifest["verificationHashes"][filename] = digest(output / filename)
        (output / spec["wrapper"]).write_bytes(wrapper)
        (output / adapter["native"]).write_bytes(native)
        (output / (spec["module"] + ".sv")).write_bytes(value)
        manifest["verificationHashes"][spec["wrapper"]] = digest(output / spec["wrapper"])
        manifest["verificationHashes"][adapter["native"]] = digest(output / adapter["native"])
        manifest["verificationHashes"][spec["module"] + ".sv"] = digest(output / (spec["module"] + ".sv"))
        manifest["wrapperAdapters"][design] = adapter
        manifest["designs"].append(design)
        for kind in ("positive", "negative"):
            name = design + "-" + kind
            case = output / "cases" / name
            case.mkdir(parents=True)
            plan = {"schema": SCHEMA, "design": design, "case": name, "kind": kind, "top": spec["top"],
                    "allAssertions": list(spec["assertions"]), "assumptions": list(spec["assumptions"]),
                    "declaredCovers": list(spec["covers"]), "sources": [spec["module"] + ".sv", adapter["native"]],
                    "inputs": [spec["module"] + ".sv", adapter["native"], "collect.tcl", "plan.tcl"],
                    "wrapperAdapter": adapter,
                    "targets": list(spec["assertions"] + spec["covers"] if kind == "positive" else [spec["negativeTarget"]]),
                    "goals": list(spec["assertions"] if kind == "positive" else [spec["negativeTarget"]]),
                    "covers": list(spec["covers"] if kind == "positive" else []),
                    "expected": "cex" if kind == "negative" else "proven", "cpuCount": 16, "outerTimeoutSeconds": 360,
                    "timeLimitSeconds": time_limit, "coverBound": cover_bound, "trustedToolSha256": tool_sha256,
                    "factsImported": False, "fullCoreProven": False}
            (case / (spec["module"] + ".sv")).write_bytes(mutate(value, spec) if kind == "negative" else value)
            (case / adapter["native"]).write_bytes(native)
            (case / "collect.tcl").write_text(COLLECTOR)
            (case / "plan.tcl").write_bytes(plan_tcl(plan))
            write_json(case / "plan.json", plan)
            manifest["cases"].append(name)
            manifest["planHashes"][name] = digest(case / "plan.json")
            manifest["inputHashes"][name] = {n: digest(case / n) for n in plan["inputs"]}
    manifest["verificationHashes"]["collect.tcl"] = hashlib.sha256(COLLECTOR.encode()).hexdigest()
    write_json(output / "manifest.json", manifest)
    return manifest


def expected_ports(design):
    result = {"clock": ("input", 1), "reset": ("input", 1)}
    if design == "sba":
        result.update({"active": ("input", 1), "accepted": ("input", 1),
                       "request_address": ("input", 7), "request_data": ("input", 32),
                       "request_op": ("input", 2), "readData": ("output", 32), "idle": ("output", 1)})
    else:
        result.update({"firstDebug": ("input", 1), "outputDebug": ("output", 1)})
    for role, upstream in (("systemBus", False),) if design == "sba" else (
            ("first", True), ("second", True), ("output", False)):
        request = "input" if upstream else "output"
        response = "output" if upstream else "input"
        result[role + "_request_valid"] = (request, 1)
        result[role + "_request_ready"] = (response, 1)
        for name, width in {"address": 32, "machine": 1, "write": 1, "data": 32,
                            "mask": 4, "size": 2, "operation": 4}.items():
            result[role + "_request_bits_" + name] = (request, width)
        result[role + "_response_valid"] = (response, 1)
        result[role + "_response_ready"] = (request, 1)
        result[role + "_response_bits_data"] = (response, 32)
        result[role + "_response_bits_fault"] = (response, 1)
    return result


def check_ports(value, design):
    spec = SPECS[design]
    header = value.decode().split("module " + spec["module"] + "(", 1)[1].split(");", 1)[0]
    actual = {}
    direction = width = None
    for field in header.split(","):
        field = field.strip()
        match = re.fullmatch(r"(input|output)\s+(?:\[(\d+):(\d+)\]\s+)?(\w+)", field)
        if match:
            direction, high, low, name = match.groups()
            width = int(high) - int(low) + 1 if high else 1
        elif re.fullmatch(r"\w+", field) and direction:
            name = field
        else:
            raise ValueError("Unexpected generated port declaration")
        if name in actual:
            raise ValueError("Duplicate generated port")
        actual[name] = (direction, width)
    if actual != expected_ports(design):
        raise ValueError("Generated pin-level contract differs")


def validate_frozen(evidence):
    manifest = json.loads((evidence / "manifest.json").read_text())
    if (manifest.get("schema") != SCHEMA or manifest.get("fullCoreProven") is not False
            or manifest.get("outerTimeoutSeconds") != 360
            or manifest.get("cpuCount") != 16 or type(manifest.get("cpuCount")) is not int
            or manifest.get("designs") not in (["sba"], ["sba", "arbiter"])):
        raise ValueError("Frozen commercial manifest differs")
    for key in ("timeLimitSeconds", "coverBound"):
        if type(manifest.get(key)) is not int or manifest[key] < 1:
            raise ValueError("Frozen query budget differs")
    if not 2 <= manifest["timeLimitSeconds"] <= 300:
        raise ValueError("Search allocation exceeds this protocol budget")
    trusted = manifest.get("trustedToolSha256")
    if trusted is not None and not re.fullmatch(r"[0-9a-f]{64}", trusted):
        raise ValueError("Frozen tool digest differs")
    names = [design + "-" + kind for design in manifest["designs"] for kind in ("positive", "negative")]
    if manifest.get("cases") != names or set(manifest.get("planHashes", {})) != set(names) or set(manifest.get("inputHashes", {})) != set(names):
        raise ValueError("Frozen case inventory differs")
    hashes = {"runner.py": digest(__file__), "backend.py": digest(backend_path()),
              "collect.tcl": hashlib.sha256(COLLECTOR.encode()).hexdigest()}
    adapters = {}
    for design in manifest["designs"]:
        spec = SPECS[design]
        original = (evidence / (spec["module"] + ".sv")).read_bytes()
        check_ports(original, design)
        wrapper = (evidence / spec["wrapper"]).read_bytes()
        adapter = wrapper_binding(wrapper, spec)
        if (evidence / adapter["native"]).read_bytes() != native_wrapper(wrapper, spec):
            raise ValueError("Frozen native reset adapter differs")
        adapters[design] = adapter
        for filename in (spec["module"] + ".sv", spec["wrapper"], adapter["native"]):
            hashes[filename] = digest(evidence / filename)
    if manifest.get("wrapperAdapters") != adapters:
        raise ValueError("Frozen reset adapter binding differs")
    if not isinstance(manifest.get("buildHashes"), dict) or set(manifest["buildHashes"]) - set(manifest["designs"]):
        raise ValueError("Frozen generation inventory differs")
    for design, expected in manifest["buildHashes"].items():
        filename = "generation-" + design + ".json"
        if digest(evidence / filename) != expected:
            raise ValueError("Frozen generation manifest differs")
        build = json.loads((evidence / filename).read_text())
        spec = SPECS[design]
        if (build.get("top") != spec["module"] or type(build.get("exitStatus")) is not int
                or build["exitStatus"] != 0 or build.get("rtlHashes", {}).get(spec["module"] + ".sv") !=
                hashes[spec["module"] + ".sv"]):
            raise ValueError("Frozen generation RTL binding differs")
        hashes[filename] = expected
    if (manifest["verificationHashes"] != hashes or digest(evidence / "runner.py") != digest(__file__)
            or digest(evidence / "backend.py") != hashes["backend.py"]):
        raise ValueError("Running verifier or verification input differs")
    for name in names:
        case = evidence / "cases" / name
        plan = json.loads((case / "plan.json").read_text())
        design, kind = name.split("-", 1)
        spec = SPECS[design]
        adapter = adapters[design]
        assertions, assumptions, covers = map(list, (spec["assertions"], spec["assumptions"], spec["covers"]))
        wanted = {"schema": SCHEMA, "design": design, "case": name, "kind": kind, "top": spec["top"],
                  "allAssertions": assertions, "assumptions": assumptions, "declaredCovers": covers,
                  "sources": [spec["module"] + ".sv", adapter["native"]],
                  "inputs": [spec["module"] + ".sv", adapter["native"], "collect.tcl", "plan.tcl"],
                  "wrapperAdapter": adapter,
                  "targets": assertions + covers if kind == "positive" else [spec["negativeTarget"]],
                  "goals": assertions if kind == "positive" else [spec["negativeTarget"]],
                  "covers": covers if kind == "positive" else [], "expected": "cex" if kind == "negative" else "proven",
                  "cpuCount": 16, "outerTimeoutSeconds": 360, "timeLimitSeconds": manifest["timeLimitSeconds"], "coverBound": manifest["coverBound"],
                  "trustedToolSha256": trusted, "factsImported": False, "fullCoreProven": False}
        if plan != wanted or digest(case / "plan.json") != manifest["planHashes"][name]:
            raise ValueError("Frozen native plan differs")
        if (case / "plan.tcl").read_bytes() != plan_tcl(plan) or (case / "collect.tcl").read_text() != COLLECTOR:
            raise ValueError("Actual native query differs from frozen plan")
        for filename in plan["sources"]:
            original = (evidence / filename).read_bytes()
            expected = mutate(original, spec) if kind == "negative" and filename.endswith(spec["module"] + ".sv") else original
            if (case / filename).read_bytes() != expected:
                raise ValueError("Frozen RTL or wrapper differs")
        if {filename: digest(case / filename) for filename in plan["inputs"]} != manifest["inputHashes"][name]:
            raise ValueError("Frozen native inputs differ")
    if {p.name for p in (evidence / "cases").iterdir()} != set(names):
        raise ValueError("Extra case directory")
    return manifest


def canonical(value):
    return value.removeprefix("<embedded>::")


def check_protocol(records, plan):
    if records.get(("run", "state")) != "complete":
        raise ValueError("Native collection did not finish")
    if any(records.get(("setup", key)) != "0" for key in ("bbox_inst", "bbox_mod", "bbox_out", "stopat")):
        raise ValueError("Native design contains an abstraction")
    assertions = [plan["top"] + "." + name for name in plan["allAssertions"]]
    assumptions = [plan["top"] + "." + name for name in plan["assumptions"]]
    covers = [plan["top"] + "." + name for name in plan["declaredCovers"]]
    source = plan["allAssertions"] + plan["assumptions"] + plan["declaredCovers"]
    baseline = None
    query_tags = [q[0] + side for q in queries(plan) for side in (".before", ".after")]
    for tag in ["setup", *query_tags, "final"]:
        current = {}
        for field in ("native_assertions", "native_assumptions", "native_covers"):
            raw = records.get((tag, field))
            if raw is None:
                raise ValueError("Native inventory snapshot is missing")
            values = raw.split()
            if len(values) != len(set(values)) or values != sorted(values):
                raise ValueError("Duplicate or unordered native inventory")
            current[field] = values
        if current["native_assertions"] != sorted(assertions) or current["native_assumptions"] != sorted(assumptions):
            raise ValueError("Native assertion or assumption inventory differs")
        if not set(covers).issubset(current["native_covers"]):
            raise ValueError("Declared native cover is missing")
        for item in set(current["native_covers"]) - set(covers):
            match = re.fullmatch(re.escape(plan["top"]) + r"\.([A-Za-z_][A-Za-z0-9_]*):precondition[1-9][0-9]*", item)
            if not match or match[1] not in source:
                raise ValueError("Unexpected automatic native cover")
        if baseline is None:
            baseline = current
        elif current != baseline:
            raise ValueError("Native inventory changed")
    for tag in [*query_tags, "final"]:
        if (records.get((tag, "clock"), "").strip() != "{clock clock 1 1}"
                or records.get((tag, "reset")) != RESET
                or sorted(canonical(item) for item in records.get((tag, "global"), "").split()) != sorted(assumptions)
                or records.get((tag, "reset_assumptions")) not in ("", "assume:0")):
            raise ValueError("Native clock, reset or global environment differs")
        if tag != "query0.before" and any(records.get((tag, key)) != records.get(("query0.before", key))
                                   for key in ("clock", "reset", "global", "reset_assumptions")):
            raise ValueError("Native proof scope changed")
        for name in source:
            kind = "assert" if name in plan["allAssertions"] else "assume" if name in plan["assumptions"] else "cover"
            prefix = tag + "." + name
            row = {key: records.get((prefix, key)) for key in META + RAW}
            optional = ("clock", "edge") + (ASSUMPTION_PROOF_FIELDS if kind == "assume" else ())
            if (any(value is None for value in row.values())
                    or any(row[key] == "__missing__" for key in META + RAW if key not in optional)):
                raise ValueError("Incomplete native property metadata or raw fields")
            for key in ("min_length", "max_length", "target_bound", "trace_length"):
                if kind == "assume" and key in ASSUMPTION_PROOF_FIELDS and row[key] == "__missing__":
                    continue
                if not re.fullmatch(r"[0-9]+", row[key]) and not (key in ("min_length", "max_length") and row[key] == "infinite"):
                    raise ValueError("Native raw length or bound is invalid")
            native_ids = (plan["top"] + "." + name, ("::" if kind == "assume" else "<embedded>::") + plan["top"] + "." + name)
            if (row["native_id"] not in native_ids
                    or canonical(row["name"]) != plan["top"] + "." + name or row["type"] != kind
                    or row["command"] != kind or row["disabled"] != "0"
                    or row["clock"] not in ("__missing__", "clock") or row["edge"] not in ("__missing__", "posedge")
                    or row["expression"] in ("", "__missing__") or row["precondition"] != "0"):
                raise ValueError("Native property identity differs")
            if tag != "query0.before" and any(row[key] != records[("query0.before." + name, key)] for key in META):
                raise ValueError("Native property identity changed")
            if kind == "assume":
                if row["validity_status"] != "temporary" or row["run_status"] != "unprocessed" or row["target_bound"] != "0":
                    raise ValueError("Native source assumption status differs")
                if tag != "query0.before" and any(row[key] != records[("query0.before." + name, key)] for key in RAW):
                    raise ValueError("Native source assumption fields changed")
    for tag, kind, seconds, engines, iteration, labels in queries(plan):
        expected_query = {"labels": " ".join(labels), "time_limit": str(seconds),
                          "per_engine_max_jobs": "4", "proven_facts_imported": "0",
                          "engines": engines, "iteration_cap": iteration, "command_attempted": "1",
                          "actual_properties": " ".join(records[(tag + ".before." + name, "native_id")] for name in labels),
                          "first_trace_attempt": "1" if kind == "covers" else "none",
                          "per_property_time_limit": "none" if kind == "covers" else str(seconds * 64)}
        if any(records.get((tag, key)) != value for key, value in expected_query.items()):
            raise ValueError("Actual native query differs")
    if {group for group, _ in records if re.fullmatch(r"query[0-9]+", group)} != {q[0] for q in queries(plan)}:
        raise ValueError("Unexpected native query inventory")
    if plan["kind"] == "positive":
        for name in plan["goals"]:
            initial = {key: records[("query0.after." + name, key)] for key in RAW}
            if (initial["validity_status"] != "proven" or initial["run_status"] != "processed"
                    or initial["min_length"] != "infinite" or initial["max_length"] != "infinite"
                    or initial["target_bound"] != "0" or initial["engine"] not in ENGINES):
                raise ValueError("Safety query did not finish with native unbounded proof")
            for tag in ("query1.before", "query1.after", "final"):
                if any(records[(tag + "." + name, key)] != initial[key] for key in RAW):
                    raise ValueError("Proven safety raw fields changed during coverage")
    evidence = {}
    for name in plan["targets"]:
        row = {key: records[("final." + name, key)] for key in RAW}
        if row["run_status"] != "processed":
            raise ValueError("Native target was not processed")
        if plan["kind"] == "positive" and name in plan["goals"]:
            if (row["validity_status"] != "proven" or row["min_length"] != "infinite"
                    or row["max_length"] != "infinite" or row["target_bound"] != "0" or row["engine"] not in ENGINES):
                raise ValueError("Safety target has no native unbounded proof")
        else:
            after = "query1.after" if name in plan["covers"] else "query0.after"
            stage = {key: records[(after + "." + name, key)] for key in RAW}
            if (stage["validity_status"] != ("covered" if name in plan["covers"] else "cex")
                    or stage["run_status"] != "processed" or int(stage["trace_length"]) < 1
                    or stage["latest_trace_engine"] not in ENGINES | {"B", "Ht", "H"}):
                raise ValueError("Native witness query did not finish effectively")
            if stage != row:
                raise ValueError("Native witness raw fields changed after its query")
        evidence[name] = row
    return {"case": plan["case"], "caseAccepted": True, "targets": evidence,
            "unboundedAssertions": len(plan["goals"]) if plan["kind"] == "positive" else 0,
            "coversReached": len(plan["covers"]) if plan["kind"] == "positive" else 0,
            "effectiveNegatives": 1 if plan["kind"] == "negative" else 0,
            "actualNativeCoverInventory": baseline["native_covers"], "fullCoreProven": False}


def check_case(case, plan, manifest):
    receipt = json.loads((case / "receipt.json").read_text())
    completion = json.loads((case / "completion.json").read_text())
    expected = {name: digest(case / name) for name in plan["inputs"]}
    cpus = receipt.get("cpuAffinity")
    if (receipt.get("command") != ["jg", "-no_gui", "-fpv", "-tcl", "collect.tcl"]
            or receipt.get("inputHashes") != expected or type(receipt.get("pid")) is not int or receipt["pid"] < 1
            or type(receipt.get("cpuCount")) is not int or receipt["cpuCount"] != 16
            or not isinstance(cpus, list) or len(cpus) != 16 or any(type(n) is not int or n < 0 for n in cpus)
            or cpus != list(range(cpus[0], cpus[0] + 16)) or type(receipt.get("cpu")) is not int or receipt["cpu"] != cpus[0]
            or type(receipt.get("timeoutSeconds")) is not int or receipt["timeoutSeconds"] != 360):
        raise ValueError("Native receipt or resource allocation differs")
    for value in (receipt.get("launcherSha256"), completion.get("nativeExecutableSha256")):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("Native tool identity is missing")
    if receipt["launcherSha256"] != completion["nativeExecutableSha256"]:
        raise ValueError("Native launcher and executed tool identity differ")
    if manifest["trustedToolSha256"] is not None and receipt["launcherSha256"] != manifest["trustedToolSha256"]:
        raise ValueError("Native tool differs from expected digest")
    if (type(completion.get("exitStatus")) is not int or completion["exitStatus"] != 0
            or completion.get("timedOut") is not False or completion.get("inputsUnchanged") is not True
            or completion.get("outputHashes") != backend().output_hashes(case)):
        raise ValueError("Native execution or output integrity failed")
    for key, source in (("startedUtc", receipt), ("endedUtc", completion)):
        value = source.get(key)
        if not isinstance(value, str) or datetime.fromisoformat(value).utcoffset() is None:
            raise ValueError("Native timestamp is absent or has no timezone")
    elapsed = completion.get("elapsedSeconds")
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
        raise ValueError("Native elapsed time is invalid")
    result = check_protocol(backend().read_records(case / "native.tsv"), plan)
    witnesses = plan["covers"] if plan["kind"] == "positive" else plan["targets"]
    for label in witnesses:
        path = case / (label + ".vcd")
        if not path.is_file() or path.name not in completion["outputHashes"]:
            raise ValueError("Required native witness is missing")
        text = path.read_text()
        if not all(token in text for token in ("$var", "$enddefinitions", "#")):
            raise ValueError("Native witness is not a populated VCD")
    result["witnessHashes"] = {label: digest(case / (label + ".vcd")) for label in witnesses}
    return result


def validate(evidence, selected=None):
    manifest = validate_frozen(evidence)
    names = [selected] if selected is not None else manifest["cases"]
    if any(name not in manifest["cases"] for name in names):
        raise ValueError("Selected case is not frozen")
    outcomes = [check_case(evidence / "cases" / name,
                           json.loads((evidence / "cases" / name / "plan.json").read_text()), manifest)
                for name in names]
    complete = names == manifest["cases"]
    return {"schema": SCHEMA, "caseAccepted": True, "commercialGate": "passed" if complete else "not_evaluated",
            "allDeclaredCasesPassed": complete, "outcomes": outcomes,
            "unboundedAssertions": sum(row["unboundedAssertions"] for row in outcomes),
            "coversReached": sum(row["coversReached"] for row in outcomes),
            "effectiveNegatives": sum(row["effectiveNegatives"] for row in outcomes),
            "fullCoreProven": False,
            "scope": "standalone SBA and optional two-input memory arbiter; no complete Debug or core proof"}


def collect(evidence, private_output, executable="jg", selected=None):
    manifest = validate_frozen(evidence)
    private_output.mkdir(parents=True, exist_ok=True)
    names = [selected] if selected is not None else manifest["cases"]
    if any(name not in manifest["cases"] for name in names):
        raise ValueError("Selected case is not frozen")
    if any((evidence / "cases" / name / artifact).exists() for name in names
           for artifact in ("receipt.json", "completion.json")):
        raise ValueError("Native attempt already exists; no restart or implicit resume")
    for name in names:
        case = evidence / "cases" / name
        legacy_error = None
        try:
            backend().collect_case(case, executable, private_output, 360, cpu_count=16)
        except (ValueError, KeyError) as error:
            if not (case / "receipt.json").is_file() or not (case / "completion.json").is_file():
                raise
            legacy_error = type(error).__name__
        # The shared transport's old bridge-specific post-check does not define this protocol.
        result = validate(evidence, name)
        write_json(case / "validation.json", {**result, "legacyPostcheckErrorClass": legacy_error})
    return validate(evidence, selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("prepare")
    command.add_argument("--rtl", type=Path, required=True)
    command.add_argument("--arbiter-rtl", type=Path)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--time-limit", type=int, default=300)
    command.add_argument("--cover-bound", type=int, default=64)
    command.add_argument("--tool-sha256")
    for name in ("collect", "validate"):
        command = commands.add_parser(name)
        command.add_argument("--evidence", type=Path, required=True)
        command.add_argument("--case")
        if name == "collect":
            command.add_argument("--private-output", type=Path, required=True)
            command.add_argument("--jg", default="jg")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare(args.rtl, args.output, args.arbiter_rtl, args.time_limit, args.cover_bound, args.tool_sha256)
            validate_frozen(args.output)
        elif args.command == "collect":
            result = collect(args.evidence, args.private_output, args.jg, args.case)
            write_json(args.evidence / "summary.json", result)
        else:
            result = validate(args.evidence, args.case)
            write_json(args.evidence / "summary.json", result)
    except (ValueError, KeyError, OSError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
