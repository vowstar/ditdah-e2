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

Ordinary read requests use a zero mask. Data accesses require natural alignment.
Alignment faults prevent external issue. Failed writes must have no external effect.
Instruction memory must have no read side effects.
Completed stores must be visible to later instruction fetches.
Cold reset is synchronous and active high. Apply it only with no offered or outstanding peer requests.
It clears integer registers and protocol state. Core reset does not initialize memory contents.

`misa` is fixed by configuration.

The retirement port reports completed instructions and synchronous exceptions.
