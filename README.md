# DitDah-E2

DitDah-E2 is a three-stage RV32 processor for embedded control.
It issues at most one instruction per cycle and preserves program order.
The full configuration enables RV32IMC, Zicsr, Zicntr, Zifencei, A, Zba, Zbb, Zbs, protectedMode and debug with an explicit JTAG IDCODE.
It includes precise traps, software, timer and external interrupts, counters, MRET and WFI; each option can be disabled independently.

| Option | Default | Effect |
| --- | --- | --- |
| `enableM`, `enableC` | True | Integer multiplication and division, compressed instructions |
| `protectedMode` | False | M/U privilege modes, counter permissions and 16 PMP entries |
| `enableDebug` | False | Synchronous DMI, halt, resume, single step and abstract register and memory access |
| `enableJtag` | False | JTAG DTM/CDC instead of external DMI; requires `enableDebug` and `jtagIdcode` |
| `enableZba`, `enableZbb`, `enableZbs` | False | Standard address, basic and single-bit operations |
| `enableA` | False | Word atomics through an atomic memory interface |

Protected configurations support only M and U modes; S mode and an MMU are absent.

## Build

```sh
nix build .#default .#software --no-link
nix develop .
```

The Nix lock pins Zaozi and CIRCT. Nix reads Git-tracked files.
`python3 scripts/build_rtl.py --config input.json --output result/rtl` generates SystemVerilog.
The JSON configuration accepts the options above and `resetVector`, which defaults to zero.
The reset address must be halfword aligned with C enabled, otherwise word aligned.

## Verify

Start with the fast compliance gate, then run the full signoff:

```sh
make verify-compliance
make verify-signoff
```

Verification combines directed simulation, independent architectural models, bounded formal checks and commercial proofs.
Commercial proof verdicts are the acceptance gate; open-source runs provide reference coverage and do not downgrade accepted commercial results.
Compilation alone is not proof.
Use a zero `resetVector` for `verify-signoff`, `verify-formal`, `verify-throughput` and RVFI profiles.

```sh
make verify-rvfi RVFI_RTL=result/rtl RVFI_OUTPUT=result/rvfi
```

RVFI profiles require a zero reset address, with A and debug disabled. B checks require all three bit options, with M and C disabled.
RVFI checks are bounded and do not establish complete ISA conformance or physical signoff.

For Sail, generate RTL at `0x80000000` and use a new output directory:

```sh
printf '%s\n' '{"resetVector":2147483648}' > result/reset.json
python3 scripts/build_rtl.py --config result/reset.json --output result/isa-rtl
make verify-sail SAIL_PROFILES=imc=result/isa-rtl SAIL_OUTPUT=result/sail
```

[Architectural tests](test/test_isa/README.md) lists other ISA profiles and their configurations.
Sail checks instruction events and memory signatures from the same ELF; external interrupts, debugger intervention and external time are excluded.

### Platforms and commercial arithmetic

`make PLATFORM_OUTPUT=result/platform-check verify-platform` executes a timer program through the AXI4-Lite adapter and console.
`make CONFIG=input.json verify-debug` requires direct DMI debug enabled and a zero reset address. `make verify-jtag` checks asynchronous transport; `make DEBUG_HOST_OUTPUT=result/jtag-host verify-debug-host` runs OpenOCD/GDB with abstract memory access.
`make CONFIG=input.json PLATFORM_OUTPUT=result/atomic-check verify-atomic` uses the shared SRAM platform with the default map and a zero reset address.
Use this configuration for its complete program collection:

```json
{"enableA": true, "enableDebug": true, "protectedMode": true}
```

`DitDahE2Platform` requires A disabled. `DitDahE2AtomicPlatform` requires A enabled.

`make verify-arithmetic` requires licensed JG as `jg` or `JG_BIN` and generated M-enabled RTL in `ARITHMETIC_RTL`.
It proves 32-bit unit results after initial reset from native properties and independent Z3 rules.
`ARITHMETIC_OUTPUT/replay/result.json` reports `operationsAccepted=8` and `fullUnitMProven=true` for a complete run.
This is a full-unit arithmetic proof, not a full-core proof or complete RVFI coverage.
`make DEBUG_TRANSPORT_OUTPUT=result/debug-commercial verify-debug-commercial` requires licensed JG and proves transport safety with covers and negative controls under the documented reset and digital-CDC assumptions.

### Outputs and reports

Use new directories for `PLATFORM_OUTPUT`, `GENERIC_OUTPUT`, `DEBUG_LATENCY_OUTPUT`, `PMP_DATA_OUTPUT`, `INTERRUPT_OUTPUT`, `FETCH_PERFORMANCE_OUTPUT`, `ISA_MENVCFG_OUTPUT`, `RVFI_OUTPUT`, `SAIL_OUTPUT`, `ARITHMETIC_OUTPUT`, `JTAG_OUTPUT`, `JTAG_CORE_OUTPUT`, `DEBUG_HOST_OUTPUT` and `DEBUG_TRANSPORT_OUTPUT`.
Set `SAIL_PROFILES`, `RVFI_RTL` and `ARITHMETIC_RTL` when selecting generated inputs.
Reports are written under `result/`, including `result/verification/summary.json` and `ARITHMETIC_OUTPUT/replay/result.json`.
RVFI and Sail write `summary.json` under their selected output directories.
[Integration](doc/microarchitecture.md) defines the memory and reset contracts.

## License

Project-authored files use the MIT license. `REUSE.toml` records file declarations.

## Credits

DitDah-E1 and DitDah-A1 provided project organization and development conventions.
The Nix toolchain shares code with DitDah-E1.
[Zaozi](https://github.com/xinpian-tech/zaozi) provides hardware description and pinned tools.
[riscv-formal](https://github.com/YosysHQ/riscv-formal) supplies the native RVFI checkers.
[Sail RISC-V](https://github.com/riscv/sail-riscv) supplies the independent instruction model.
