<!-- SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> -->
<!-- SPDX-License-Identifier: MIT -->

# Integration

F fetches instructions, X executes them, and M completes memory work and commits results.
The core uses little-endian memory and separate instruction and data ports.

Each native port permits one outstanding transaction through ready/valid channels.
A rising edge with valid and ready high transfers the request or response.
The producer holds valid and payload until acceptance.
Each accepted request requires exactly one response, at least one cycle later.
Redirects discard younger instructions but retain offered and accepted requests until they drain.

| Field | Meaning |
| --- | --- |
| address | 32-bit byte address |
| write, data, mask | Write selection, lane-aligned data and four byte enables |
| size | Zero for a byte, one for a halfword, two for a word |
| response data, fault | Aligned read word and access-fault indication |
| machine | Effective privilege, one for M and zero for U |
| operation | Zero for ordinary access, otherwise the atomic code below |

Ordinary read requests use a zero mask. Data accesses require natural alignment.
Alignment faults prevent external issue. Failed writes must have no external effect.
Instruction memory must have no read side effects.
Completed stores must be visible to later instruction fetches.
Cold reset is synchronous and active high. Apply it only with no offered or outstanding peer requests.
It clears integer registers and protocol state. Core reset does not initialize memory contents.

FENCE.I drains fetch and restarts at its saved next PC.
Compressed HINTs execute their ordinary expansion and preserve architectural register values.

Permission faults prevent external issue.

| Atomic code | Operation |
| --- | --- |
| 1, 2 | LR.W, SC.W |
| 3, 4, 5 | AMOSWAP.W, AMOADD.W, AMOXOR.W |
| 6, 7 | AMOAND.W, AMOOR.W |
| 8, 9, 10, 11 | AMOMIN.W, AMOMAX.W, AMOMINU.W, AMOMAXU.W |

Atomics use aligned words. AMOs require read and write permission.
The atomic endpoint must serialize all competing writers and reservation changes.
SC returns zero on success and one on reservation failure. AMOs return the previous word.
The ordered data path completes each access before the next, for all aq and rl combinations.

`platform.json` defines the memory map for `DitDahE2Platform`.

`DitDahE2Platform` requires A disabled. `DitDahE2AtomicPlatform` requires A enabled.
Atomics outside shared SRAM fault. The AXI4-Lite adapter rejects atomics without bus activity.
Shared SRAM serializes instruction, data, debug and competitor accesses through one controller.
Writes to the reserved word invalidate the reservation. Every SC attempt clears it.
Trap entry, MRET, permission updates, debug transitions and reset also clear it.

`protectedMode` provides M and U with 16 PMP entries and four-byte granularity.
PMP supports TOR, NA4 and NAPOT. The first matching entry must cover the whole access.
Locked entries also constrain M mode. MPRV selects data privilege from MPP, without changing fetch privilege.
PMP updates drain fetch. MRET to U clears MPRV.
Debug resume to U also clears MPRV.

`misa` is fixed by configuration.
HPM state and `mstatush` read zero and ignore writes. Identification registers are read-only zero.
Protected `menvcfg` and `menvcfgh` read zero and ignore writes. M-only mode has neither.

Interrupt inputs are synchronous and require external synchronization.
Interrupt priority is external, software, then timer. Older synchronous exceptions complete first.
The platform supplies coherent 64-bit time.

`enableDebug` exposes synchronous DMI when JTAG is disabled. Synchronize it externally.
`enableJtag` requires Debug and an explicit IDCODE, replacing the external DMI pins with a five-bit TAP/DTM and single-outstanding CDC.
Counters stop while halted, while platform time continues.
Halt drains older work before register or abstract memory access.
Debug memory uses M privilege with MPRV applied. Its faults do not change machine trap CSRs.
AAM postincrement updates data1 once after each successful access by its encoded byte size; faults do not increment it.
`abstractauto` implements data0, data1, progbuf0 and progbuf1. Each accepted automatic access resamples current operands; a data0 read snapshots its old result before starting, and response backpressure cannot repeat execution.
The two Program Buffer words report `abstractcs.progbufsize=2` and `dmstatus.impebreak=1`, and end with an implicit EBREAK when exhausted. `postexec` executes them once after an optional register transfer, while `transfer=0` leaves data0 unchanged; a successful read remains valid when later buffer execution faults.
Injected execution keeps the hart halted and suppresses native fetch, interrupts, triggers and retirement. Faults set `cmderr=3` without changing native trap CSRs; DCSR and DPC instructions update the live debug state. Accepted native transfers drain before command completion, deactivation or reset proceeds.
Compressed halfwords may cross the word boundary; a truncated final halfword faults. Branches, jumps, AUIPC, MRET and FENCE.I are rejected, WFI is a NOP, and explicit or implicit EBREAK completes without a fault. Quick Access and SBA are absent.
Single step completes one instruction or exception with interrupts masked, then halts.
Warm reset drains Core and debug transfers before resetting the hart. The debug module remains available.
Already accepted competitor transactions complete across warm reset.

`triggerCount` is zero or two; two requires Debug and zero omits the trigger bank.
The bank provides `tselect`, `tdata1-3`, `tinfo`, `tcontrol` and zero-valued context registers.
`tinfo.version` is one and only mcontrol type two is advertised. Exact execute-address matching is supported.
Debug owns `dmode`; M-mode writes to a Debug-owned trigger are ignored. `dmode=0, action=1` coerces to action zero.
A match uses an accepted X instruction after older M work completes, never a speculative fetch PC.
The matching instruction has no memory, CSR, multiply or retirement side effects before the selected action.
Action zero raises breakpoint cause three with its PC in `mepc` and `mtval`; action one enters Debug with DPC at that PC.
All simultaneous hit bits are recorded and Debug entry suppresses a coincident native breakpoint.
Trap entry saves `tcontrol.mte` to `mpte` and clears `mte`; MRET restores it to prevent native-trigger loops.
Triggers do not fire in Debug Mode or injected execution. Watchpoints, exception, interrupt, icount and chains are absent.

The retirement port reports completed instructions and synchronous exceptions.
Its order starts at zero after reset and increments for each valid event.
It includes source values, aligned memory lanes, explicit CSR access and CSR state before and after the instruction.
Counter after values contain only explicit instruction writes and otherwise equal their before values.
The handler marker identifies the first instruction after a synchronous trap or interrupt entry.
AMO write data is the request operand. Check the actual SRAM write at the atomic endpoint.
Debug EBREAK emits no retirement event.
A separate interrupt event carries the interrupted PC, target and cause.
It also carries privilege and trap CSR state before and after entry.

## Verification scope

`make verify-signoff` runs the functional gate for the selected RTL configuration.
The trigger commercial gate separately requires all 17 fixed cases to pass.
Trigger proofs use four fixed ROM programs, directed DMI setup and one initial reset.
Memory responses follow the ideal one-cycle model.
Each trigger core safety case must pass all 21 original goals.
Each goal needs an unbounded proof or a qualified finite result at its own original bound.
Goals declared unbounded require native unbounded proof.
Covers and expected counterexamples retain their recorded acceptance conditions.
Reuse requires identical complete case plans and native inputs, with original receipts and outputs preserved.
Tool identities and verifier contracts must also match.
The selected profile reuses only native unbounded facts from the same task.
Source diagnostics and helper proofs do not replace original goals.
These gates do not prove arbitrary programs or establish complete ISA conformance or physical signoff.
