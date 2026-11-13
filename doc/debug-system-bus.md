# System bus access

`enableSba=true` requires `enableDebug=true`. It adds a separate `systemBus` memory master to `DitDahE2` and implements the single-hart SBA registers from the [RISC-V Debug Specification 1.0](https://docs.riscv.org/reference/debug/v1.0/debug_module.html).
The bus has 32-bit physical addresses, supports 8/16/32-bit accesses and permits one outstanding transfer.
It operates independently of the hart's running/halted state and abstract-command execution.

| DMI address | Register | Implemented behavior |
| --- | --- | --- |
| `0x38` | `sbcs` | Version 1, address size 32, access widths, busy, sticky errors and controls |
| `0x39` | `sbaddress0` | Physical byte address; writes can initiate reads |
| `0x3c` | `sbdata0` | Read result or write operand; reads can initiate the next read |

`sbcs` resets to `0x20040407`: 32-bit access selected, no read triggers or autoincrement, no errors.
Read-on-address, read-on-data and autoincrement are configurable. Reading `sbdata0` snapshots the old result before a new read starts.
Addresses increment by the selected width only after successful bus completion, including successful writes.
Narrow reads are zero extended; write operands occupy the low bits and the bus request supplies aligned byte lanes.
Unsupported widths set `sberror=4`, misalignment sets `3`, and a bus fault sets `2`.
Errors are sticky and inhibit new operations until cleared with write-one-to-clear fields in `sbcs`.
Data accesses or address writes while busy set `sbbusyerror`; control writes while busy are ignored.
The implementation has no timeout counter; the target must eventually respond to every accepted request.
Unimplemented address/data words read as zero and ignore writes. There is no 64/128-bit transfer support.

## Integration

`systemBus` follows the same ready/valid contract as the native data port: an offered request stays stable until acceptance, and each accepted request receives exactly one response no earlier than the next cycle.
Reads return the addressed aligned 32-bit word; faults on writes must have no device effect.
SBA uses physical M-privilege bus requests and bypasses hart translation, PMP and MPRV. The integrator controls debugger access to the system address map.

Both platform wrappers arbitrate core data and SBA before address decoding, alternating priority after completion when both sources assert request valid.
Arbitration locks the source at its first offer, including during request backpressure, and holds response ownership until consumption.
The atomic platform routes SBA SRAM accesses through the debug endpoint of the shared atomic controller.
A successful SBA write to the reserved word invalidates the hart's LR/SC reservation; writes to another word preserve it.
The AXI4-Lite platform has no atomic endpoint and requires A disabled.

`dmactive=0` resets the SBA register bank while offered and accepted transfers continue to drain; their results cannot update a later activation.
If reactivation arrives before draining finishes, the module holds `dmactive=0` until the old owner completes. Debuggers must poll `dmactive`.
`ndmreset` blocks new SBA operations and queues the hart reset until SBA is idle.
Clearing the bit before bus completion does not cancel that request. Warm reset preserves the SBA register bank.
Deactivating the DM cancels a queued reset that has not yet been sent to the hart; a reset already received by the hart continues independently.
The cold reset contract requires all bus peers to be quiescent.
The platforms contain no caches; adding caches requires an explicit system-bus coherence policy.

## Build and check

```sh
make verify-sba SBA_OUTPUT=result/sba-check
```

The gate checks an independent byte-memory model, DMI response backpressure, activation/reset boundaries, arbitration, both complete platforms and real OpenOCD/GDB sessions.
The atomic platform test executes LR/SC across same-word and different-word SBA writes without an intervening hart-control reservation clear.
Host tests force `riscv set_mem_access sysbus`, check halted/running memory accesses and reject abstract-memory or Program Buffer memory fallback.
On an integrated target, select that OpenOCD command after configuring the JTAG tap and target; the test harness supplies its own simulated memory map.
Enable GDB data-abort reporting before OpenOCD `init`; otherwise failed reads can appear as zero data. The harness supports both command spellings:

```tcl
if {[catch {gdb report_data_abort enable}]} {gdb_report_data_abort enable}
```

`make verify-sba-reference` runs bounded safety checks and cover witnesses with open-source tools.
`make verify-sba-commercial` runs the separately scoped licensed proof gate. It does not prove arbitrary core programs, target liveness, cache coherence or physical implementation.
Use a new `SBA_OUTPUT` directory for each run. Reports bind the selected configuration, source inputs, generated RTL, checker and tool identities.
