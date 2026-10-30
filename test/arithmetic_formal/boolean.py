# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Collect and replay the sampled Boolean induction rule and its controls."""

import json
from pathlib import Path

from . import native, traces

HERE = Path(__file__).resolve().parent
CASES = ("positive", "no_base", "no_step", "bad_sample")


def expected_case(kind, time_limit):
    if kind not in CASES:
        raise ValueError("Unknown induction rule case")
    text = (HERE / "induction.sv").read_text()
    assumptions = ["base_obligation", "step_obligation"]
    if kind == "no_base":
        text = text.replace("            base_obligation: assume (!first_frame || I);\n", "")
        assumptions.remove("base_obligation")
    elif kind == "no_step":
        text = text.replace(
            "            step_obligation: assume (first_frame || !previous_I || I);\n", ""
        )
        assumptions.remove("step_obligation")
    elif kind == "bad_sample":
        text = text.replace("previous_I <= I;", "previous_I <= !I;")
    plan = {
        "top": "boolean_induction_rule",
        "sources": ["rule.sv"],
        "goals": [["rule_conclusion", []]],
        "expected": "proven" if kind == "positive" else "cex",
        "covers": ["base_is_satisfiable", "step_is_satisfiable"] if kind == "positive" else [],
        "assumptions": ["boolean_induction_rule." + name for name in assumptions],
        "timeLimitSeconds": time_limit,
    }
    files = {
        "rule.sv": text.encode(),
        "collect.tcl": (HERE / "collect.tcl").read_bytes(),
        "plan.tcl": native.tcl_plan(plan).encode(),
    }
    plan["inputs"] = sorted(files)
    return plan, files


def prepare(directory, time_limit):
    directory.mkdir(parents=True, exist_ok=False)
    for kind in CASES:
        case = directory / kind
        case.mkdir()
        plan, files = expected_case(kind, time_limit)
        for name, value in files.items():
            (case / name).write_bytes(value)
        (case / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")


def validate(directory, time_limit):
    for kind in CASES:
        case = directory / kind
        plan, files = expected_case(kind, time_limit)
        if json.loads((case / "plan.json").read_text()) != plan:
            raise ValueError("The induction rule native plan changed")
        if any((case / name).read_bytes() != value for name, value in files.items()):
            raise ValueError("The induction rule source changed")


def collect(directory, executable, private, timeout):
    for kind in CASES:
        native.collect(directory / kind, executable, private, timeout)


def replay_trace(path, kind, cover=None):
    fields = ("clock", "reset", "I", "first_frame", "previous_I")
    derived_previous = kind == "no_step" and not any(
        line.split()[4] == "previous_I"
        for line in path.read_text().splitlines()
        if line.startswith("$var ")
    )
    observed = (
        tuple(name for name in fields if name != "previous_I") if derived_previous else fields
    )
    samples = traces.frames(
        path, {name: ("boolean_induction_rule." + name, 1) for name in observed}
    )
    if derived_previous:
        for index, row in enumerate(samples):
            row["previous_I"] = samples[index - 1]["I"] if index else 1
    if samples[0]["first_frame"] != 1 or samples[0]["previous_I"] != 1:
        raise ValueError("The induction rule trace has no valid initial frame")
    for index, row in enumerate(samples):
        if row["reset"]:
            raise ValueError("The induction trace includes an unchecked reset")
        if index:
            previous = samples[index - 1]["I"]
            expected = 1 - previous if kind == "bad_sample" else previous
            if row["first_frame"] or row["previous_I"] != expected:
                raise ValueError("The induction rule samples the wrong predicate")
        if kind != "no_base" and row["first_frame"] and not row["I"]:
            raise ValueError("The induction trace violates the base premise")
        if kind != "no_step" and not row["first_frame"] and row["previous_I"] and not row["I"]:
            raise ValueError("The induction trace violates the step premise")
    if kind == "positive":
        if not all(row["I"] for row in samples):
            raise ValueError("The native induction cover violates its conclusion")
        if cover == "base":
            reached = any(row["first_frame"] and row["I"] for row in samples)
        elif cover == "step":
            reached = any(
                not row["first_frame"] and row["previous_I"] and row["I"] for row in samples
            )
        else:
            raise ValueError("Unknown induction cover")
    elif kind == "no_base":
        reached = any(row["first_frame"] and not row["I"] for row in samples)
    elif kind == "no_step":
        reached = any(
            not row["first_frame"] and row["previous_I"] and not row["I"] for row in samples
        )
    else:
        reached = any(
            index
            and not row["first_frame"]
            and not row["previous_I"]
            and not row["I"]
            and samples[index - 1]["I"]
            for index, row in enumerate(samples)
        )
    if not reached:
        raise ValueError("The induction trace does not reach its required control")
    return {
        "replayed": True,
        "samples": len(samples),
        "sha256": native.digest(path),
        "unusedObserverDerivedFromActualPast": derived_previous,
    }


def replay(directory, time_limit):

    validate(directory, time_limit)
    controls = {}
    for kind in CASES:
        case = directory / kind
        native.validate_case(case, json.loads((case / "plan.json").read_text()))
        if kind == "positive":
            controls["base"] = replay_trace(case / "base_is_satisfiable.vcd", kind, "base")
            controls["step"] = replay_trace(case / "step_is_satisfiable.vcd", kind, "step")
        else:
            controls[kind] = replay_trace(case / "rule_conclusion.vcd", kind)
    return {
        "accepted": True,
        "nativeAssertionsProven": 1,
        "coversReplayed": 2,
        "negativeControlsReplayed": 3,
        "architecturalEnvironmentAssumptionsAdded": 0,
        "localRulePremises": ["First frame implies I", "Previous I implies current I"],
        "controls": controls,
    }
