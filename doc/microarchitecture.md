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

Interrupt inputs are synchronous and require external synchronization.
Interrupt priority is external, software, then timer. Older synchronous exceptions complete first.
The platform supplies coherent 64-bit time.

`enableDebug` exposes synchronous DMI. Synchronize it externally.
Counters stop while halted, while platform time continues.
JTAG transport is external. Halt drains older work before register or abstract memory access.
Debug memory uses M privilege with MPRV applied. Its faults do not change machine trap CSRs.
Single step completes one instruction or exception with interrupts masked, then halts.
Warm reset drains Core and debug transfers before resetting the hart. The debug module remains available.
Already accepted competitor transactions complete across warm reset.

The retirement port reports completed instructions and synchronous exceptions.
Debug EBREAK emits no retirement event.
A separate interrupt event carries the interrupted PC, target and cause.
