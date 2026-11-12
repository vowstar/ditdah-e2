<!--
SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
SPDX-License-Identifier: MIT
-->

# DebugHart Program Buffer formal proof

This evidence binds the two-word, compressed-capable standalone `DitDahE2DebugHart` build.
An independent wrapper model checks postexec admission, backend write isolation, fresh operands,
instruction boundaries, implicit EBREAK, cancellation, response blocking, and accepted-memory drain.
It does not prove full-core execution, injected instruction semantics, or native trap CSRs.

All safety goals require an unbounded `proven` verdict. Covers require `covered`; mutated controls
require `cex` and a VCD witness. A timeout, unknown result, blackbox, changed input, or missing
trace is a failure. The formal clock is the single `clock` input; `reset -none` leaves the initial
cold reset to global one-cycle assumptions and prohibits later cold resets.
The environment holds blocked requests stable, returns injection completion
only for an accepted sequence, reports 32-bit EBREAK completion as `ebreak`, requires accepted work
before idle, and returns memory responses only for accepted requests. Later cold reset and fairness
are outside the proof scope.

Set `PROGRAM_HART_RTL` to a new private build directory, `PROGRAM_HART_EVIDENCE` to a new private
evidence directory, and `PROGRAM_HART_PRIVATE` to a private log directory. The following commands
are the prepare/collect/validate sequence for a Make entry; `JG_ARGS` may select the licensed
executable and timeout. Collection runs one native process at a time and pins it to one CPU.

```sh
python3 test/test_debug/program_hart.py --output "$PROGRAM_HART_RTL" --enable-c
hash=$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$PROGRAM_HART_RTL/rtl/DitDahE2DebugHart.sv")
python3 -m formal.debug_program_hart.run prepare \
  --rtl "$PROGRAM_HART_RTL" --source-root . --expected-rtl-sha256 "$hash" \
  --output "$PROGRAM_HART_EVIDENCE" ${PROGRAM_HART_PREPARE_ARGS:-}
python3 -m formal.debug_program_hart.run collect \
  --evidence "$PROGRAM_HART_EVIDENCE" --private-output "$PROGRAM_HART_PRIVATE" \
  ${JG_ARGS:-}
python3 -m formal.debug_program_hart.run validate --evidence "$PROGRAM_HART_EVIDENCE"
```

Copy only `summary.json` into project results after remote collection. Keep the frozen bundle,
receipts, native records, logs, and VCD witnesses in the private run directory.
