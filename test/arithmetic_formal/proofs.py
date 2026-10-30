# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Check native facts, replay traces, and prove the complete arithmetic predicate."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess

from . import facts, native, source, traces


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def replay_solver_queries(directory, executable):
    rows = []
    for query_file in sorted(directory.rglob("queries.json")):
        queries = json.loads(query_file.read_text())
        for query in queries:
            parent = query_file.parent
            if "operation" in query and (parent / ("op" + str(query["operation"]))).is_dir():
                parent = parent / ("op" + str(query["operation"]))
            path = parent / (query["name"] + ".smt2")
            run = subprocess.run(
                [str(executable), "-T:30", "-smt2", str(path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=35,
            )
            verdicts = [
                line for line in run.stdout.splitlines() if line in ("sat", "unsat", "unknown")
            ]
            if (
                run.returncode != 0
                or run.stderr.strip()
                or verdicts != [query["expected"]]
                or query["actual"] != query["expected"]
            ):
                raise ValueError("Independent solver replay rejected a composition rule")
            rows.append(
                {
                    "query": path.relative_to(directory).as_posix(),
                    "sha256": native.digest(path),
                    "verdict": verdicts[0],
                }
            )
    if not rows:
        raise ValueError("The arithmetic composition contains no checked obligations")
    write_json(directory / "solver-replay.json", rows)
    return rows


def validate_graph(graph):
    established = set()
    for name, dependencies in graph.items():
        if name in dependencies or set(dependencies) - established:
            raise ValueError("Arithmetic proof graph is cyclic or incomplete")
        established.add(name)
    return tuple(established)


def prove_multiply(operation, contract, native_facts, output):
    from . import capture_rules, multiply_normalize, multiply_result, multiply_rules, multiply_sign

    if native_facts.get("booleanInductionRule", {}).get("accepted") is not True:
        raise ValueError("Native sampled induction rule is missing")
    required = {name for name, _ in facts.goals(operation)}
    if set(native_facts["provenLabels"]) != required or not native_facts["covers"]:
        raise ValueError("Multiplication native premises are incomplete")
    with contextlib.redirect_stdout(io.StringIO()):
        multiply_rules.prove(output / "conservation", operation)
        capture_rules.prove(output / "capture")
        multiply_sign.prove(output / "sign")
        multiply_normalize.prove(output / "normalization")
        multiply_result.prove(output / "response", operation)
    graph = {label: list(dependencies) for label, dependencies in facts.goals(operation)}
    graph.update(
        {
            "source_observers": [],
            "sampled_boolean_induction_rule": [],
            "typed_tuple_congruence": [
                "chain_actual_step_product",
                "chain_actual_step_multiplicand",
                "chain_actual_step_multiplier",
                "chain_owner_magnitudes_stable",
                "chain_initial_state",
                "chain_actual_hold_product",
                "chain_actual_hold_multiplicand",
                "chain_actual_hold_multiplier",
            ],
            "total_transition": ["typed_tuple_congruence", "chain_sampled_identity"],
            "conservation_base_and_step": [
                "sampled_boolean_induction_rule",
                "total_transition",
                "typed_tuple_congruence",
                "source_observers",
                "epoch_active_has_predecessor",
                "initial_frame_is_idle",
                "snapshot_product_is_actual_past",
                "snapshot_multiplicand_is_actual_past",
                "snapshot_multiplier_is_actual_past",
                "snapshot_owner_left_is_actual_past",
                "snapshot_owner_right_is_actual_past",
                "snapshot_owner_operation_is_actual_past",
                "snapshot_mul_step_is_actual_past",
                "snapshot_owner_is_actual_past",
            ],
            "terminal_product": [
                "conservation_base_and_step",
                "epoch_active_has_predecessor",
                "chain_terminal_total_is_product",
            ],
            "checker_capture_base_and_step": [
                "sampled_boolean_induction_rule",
                "source_observers",
                "initial_frame_is_idle",
                "pending_capture_or_hold_predecessor",
                "captured_expected_from_request",
                "captured_owner_left_from_request",
                "captured_owner_right_from_request",
                "expected_without_accept_holds",
                "owner_left_without_accept_holds",
                "owner_right_without_accept_holds",
            ],
            "standard_sign_and_projection": [],
            "response_base_and_step": [
                "sampled_boolean_induction_rule",
                "terminal_product",
                "checker_capture_base_and_step",
                "standard_sign_and_projection",
                "source_observers",
                "initial_frame_is_idle",
                "response_epoch_has_predecessor",
                "response_finish_has_actual_past_terminal_owner",
                "response_hold_has_actual_past_goal",
                "response_hold_data_matches_past",
                "response_hold_expected_matches_past",
                "snapshot_product_is_actual_past",
                "snapshot_owner_left_is_actual_past",
                "snapshot_owner_right_is_actual_past",
                "snapshot_negative_is_actual_past",
                "chain_owner_left_stable",
                "chain_owner_right_stable",
                "owner_sign",
                "chain_actual_finish_low" if operation == 0 else "chain_actual_finish_high",
            ],
        }
    )
    validate_graph(graph)
    return {
        "operation": operation,
        "proofGraph": graph,
        "functionInterpretation": "U(M64,Q32) = M64 * zero_extend(Q32) modulo 2^64",
        "referenceSubstitution": "U32(L32,R32) = U(zero_extend(L32),R32)",
        "inductionRule": "First sampled frame and universal actual preceding sample step",
        "inductionHypothesis": "Local preceding predicate inside the step only",
        "guard": contract["guard"],
        "globalResultAssumptionAdded": False,
        "originalArithmeticCompositionalProven": True,
        "nativeDirectArithmeticStatus": "not_run",
        "fullCoreMProven": False,
    }


def replay(evidence, manifest, output, z3_executable):
    verification_hashes = source.source_hashes()
    executable = Path(shutil.which(z3_executable) or z3_executable).resolve(strict=True)
    version = subprocess.run(
        [str(executable), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
    )
    if version.returncode or version.stderr.strip() or not version.stdout.startswith("Z3 version "):
        raise ValueError("The independent solver is not Z3")
    output.mkdir(parents=True, exist_ok=False)
    from . import boolean

    induction = boolean.replay(evidence / "induction", manifest["timeLimitSeconds"])
    write_json(output / "induction-replay.json", induction)
    operations = []
    for operation in manifest["operations"]:
        name = facts.INSTRUCTIONS[operation]
        result = output / name
        result.mkdir()
        positive = evidence / name / "facts"
        negative = evidence / name / "result-control"
        plan = json.loads((positive / "plan.json").read_text())
        native_result = native.validate_case(positive, plan)
        native.validate_case(negative, json.loads((negative / "plan.json").read_text()))
        covers = {
            label: traces.replay_cover(positive / (label + ".vcd"), operation, label)
            for label in plan["covers"]
        }
        control = traces.replay_result(negative / "arithmetic_matches_reference.vcd", operation)
        native_facts = {
            "booleanInductionRule": induction,
            "operation": operation,
            "provenLabels": tuple(name for name, _ in plan["goals"]),
            "assumptions": facts.ASSUMPTIONS,
            "covers": covers,
            "fullWidth": True,
            "originalGuard": True,
            "collectedSourceSha256": native.digest(positive / "bench.sv"),
            "collectedDutSha256": native.digest(positive / "DitDahE2MultiplyDivide.sv"),
        }
        if operation < 4:
            from . import multiply_contracts

            contract = multiply_contracts.bind(
                operation,
                (positive / "bench.sv").read_text(),
                (positive / "DitDahE2MultiplyDivide.sv").read_text(),
                (positive / "multiply_step.sv").read_text(),
            )
            report = prove_multiply(operation, contract, native_facts, result)
        else:
            from . import division_contracts, division_rules

            contract = division_contracts.bind_division(
                (positive / "bench.sv").read_text(),
                (positive / "DitDahE2MultiplyDivide.sv").read_text(),
                operation,
            )
            report = division_rules.prove_division(contract, native_facts, output_dir=result)
        if report.get("originalArithmeticCompositionalProven") is not True:
            raise ValueError("The complete original arithmetic predicate was not proved")
        write_json(result / "source-contracts.json", contract)
        write_json(result / "native-facts.json", native_result)
        write_json(result / "trace-replay.json", {"covers": covers, "resultControl": control})
        queries = replay_solver_queries(result, executable)
        report["solverQueries"] = len(queries)
        report["nativeGoals"] = native_result["nativeGoals"]
        write_json(result / "proof.json", report)
        operations.append(report)
    if source.source_hashes() != verification_hashes:
        raise ValueError("Verification source changed during replay")
    report = {
        "schema": "ditdah-e2.arithmetic-replay.v1",
        "operations": operations,
        "operationsAccepted": len(operations),
        "fullUnitMProven": len(operations) == 8,
        "nativeDirectArithmeticProven": False,
        "operandBitsEach": 32,
        "actualRequestOperationBits": 3,
        "resetScope": "initial_reset_only",
        "fullCoreMProven": False,
        "solver": {
            "name": "Z3",
            "version": version.stdout.strip(),
            "executableSha256": native.digest(executable),
        },
        "evidenceManifestSha256": native.digest(evidence / "manifest.json"),
        "collectionSourceHashes": manifest["sourceHashes"],
        "verificationSourceHashes": verification_hashes,
    }
    write_json(output / "result.json", report)
    return {
        "operationsAccepted": len(operations),
        "fullUnitMProven": len(operations) == 8,
        "nativeDirectArithmeticProven": False,
        "fullCoreMProven": False,
        "resultSha256": native.digest(output / "result.json"),
    }
