# DitDah-E2

DitDah-E2 is a three-stage RV32 processor for embedded control.
It issues at most one instruction per cycle and preserves program order.
The default configuration implements RV32IMC, Zicsr, Zicntr and Zifencei in machine mode.
It includes precise traps, software, timer and external interrupts, counters, MRET and WFI.

| Option | Default | Effect |
| --- | --- | --- |
| `enableM`, `enableC` | True | Integer multiplication and division, compressed instructions |
| `protectedMode` | False | User mode, counter permissions and 16 PMP entries |
| `enableDebug` | False | Synchronous DMI, halt, resume, single step and abstract register and memory access |
| `enableZba`, `enableZbb`, `enableZbs` | False | Standard address, basic and single-bit operations |
| `enableA` | False | Word atomics through an atomic memory interface |

## Build and verify

```sh
nix develop .
make verify-signoff
make verify-compliance
make verify-software
nix build .#default --no-link
```

The Nix lock pins Zaozi and CIRCT. Nix reads Git-tracked files.
`python3 scripts/build_rtl.py --config input.json --output result/rtl` generates SystemVerilog.
The JSON configuration accepts the options above and `resetVector`, which defaults to zero.
The reset address must be halfword aligned with C enabled, otherwise word aligned.

`make PLATFORM_OUTPUT=result/platform-check verify-platform` executes a timer program through the AXI4-Lite adapter and console.
`make CONFIG=input.json verify-debug` requires debug enabled and a zero reset address.
`make CONFIG=input.json PLATFORM_OUTPUT=result/atomic-check verify-atomic` uses the shared SRAM platform with the default map and a zero reset address.
Use this configuration for its complete program collection:

```json
{"enableA": true, "enableDebug": true, "protectedMode": true}
```

`DitDahE2Platform` requires A disabled. `DitDahE2AtomicPlatform` requires A enabled.

Use a zero `resetVector` for `verify-signoff`, `verify-formal`, `verify-throughput`.
Use new directories for `PLATFORM_OUTPUT`, `GENERIC_OUTPUT`, `DEBUG_LATENCY_OUTPUT`, `PMP_DATA_OUTPUT`, `INTERRUPT_OUTPUT`, `RVFI_OUTPUT`, `SAIL_OUTPUT` and `ARITHMETIC_OUTPUT`.
Selected checks do not establish complete ISA conformance or physical signoff.
`make verify-signoff` also checks retirement packets and interrupt events against the native simulation trace.
`make verify-rvfi` runs bounded external RVFI checks. Set `RVFI_RTL`, `RVFI_OUTPUT` and `RVFI_ARGS` for the selected profile.
RVFI profiles require a zero reset address, with A and debug disabled. B checks require all three bit options, with M and C disabled.
`make verify-arithmetic` requires licensed JG as `jg` or `JG_BIN` and generated M-enabled RTL in `ARITHMETIC_RTL`.
It proves 32-bit unit results after initial reset from native properties and independent Z3 rules.
`ARITHMETIC_OUTPUT/replay/result.json` reports `operationsAccepted=8` and `fullUnitMProven=true` for a complete run.
[Integration](doc/microarchitecture.md) defines the memory and reset contracts.
[Architectural tests](test/isa/README.md) lists the test commands and configurations.

## GDS utilities

Both scripts require new `--output` and `--report` paths. Use `--help` for their inputs.
`scripts/align_gds_units.py` preserves coordinate bytes and supports one SREF level with R0, R180, MX or MY and unit magnification.
Arrays, deeper references and other transforms are rejected.
`scripts/preserve_gds_structures.py` requires matching database units, unique names and complete structure references.
Unselected referenced structures must already match the library bytes.
Check layer and datatype correspondence before use.

## License

Project-authored files use the MIT license. `REUSE.toml` records file declarations.

## Credits

DitDah-E1 and DitDah-A1 provided project organization and development conventions.
The Nix toolchain shares code with DitDah-E1.
[Zaozi](https://github.com/xinpian-tech/zaozi) provides hardware description and pinned tools.
[riscv-formal](https://github.com/YosysHQ/riscv-formal) supplies the native RVFI checkers.
[Sail RISC-V](https://github.com/riscv/sail-riscv) supplies the independent instruction model.
