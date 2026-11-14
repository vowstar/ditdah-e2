# DitDah-E2

DitDah-E2 is a configurable 32-bit RISC-V processor for embedded control.
Its three-stage F / X / M pipeline is single issue and executes in program order.
It includes precise traps, machine interrupts, counters, MRET and WFI, with optional memory protection, atomics and JTAG debugging.

| Instruction configuration | ISA string |
| --- | --- |
| Default | `RV32IMC_Zicntr_Zicsr_Zifencei` |
| All instruction options | `RV32IMAC_Zicntr_Zicsr_Zifencei_Zba_Zbb_Zbs` |

Use the `ilp32` ABI. For GCC, use the lowercase ISA string with `-march` and `-mabi=ilp32`.
Privilege modes, PMP and Debug are configured separately from the ISA string.

| Option | Default | Capability |
| --- | --- | --- |
| `enableM`, `enableC` | `true` | Integer multiplication/division and compressed instructions |
| `enableZba`, `enableZbb`, `enableZbs` | `false` | Address, basic and single-bit operations |
| `enableA` | `false` | Word LR/SC and AMOs with a shared atomic memory endpoint |
| `protectedMode` | `false` | M/U privilege modes, counter permissions and 16 PMP entries |
| `enableDebug` | `false` | Halt, resume, step, abstract register/memory access and a two-word Program Buffer |
| `enableJtag` | `false` | JTAG DTM/CDC; requires Debug and an explicit `jtagIdcode` |
| `triggerCount` | `0` | Zero or two execute-address triggers; two requires Debug |
| `enableSba` | `false` | 32-bit system bus addressing with 8/16/32-bit accesses; requires Debug |

The default privilege mode is M. Protected configurations add U; S mode and an MMU are absent.
Debug supports synchronous DMI or JTAG. SBA accesses memory while the hart runs or is halted.

## Build and integrate

Enter the pinned Nix environment and generate the default SystemVerilog:

```sh
nix develop .
make rtl
```

The Nix lock pins Zaozi, CIRCT and software tools. Generated RTL and its configuration/source/tool manifest are in `result/rtl/`.
Supply options in a JSON file; `resetVector` defaults to zero and requires halfword alignment with C, otherwise word alignment.

```sh
printf '%s\n' '{"enableDebug":true,"enableSba":true}' > result/debug.json
python3 scripts/build_rtl.py --config result/debug.json --output result/debug-rtl
```

The core exposes separate instruction and data request/response ports, plus a separate system bus master when SBA is enabled.
`DitDahE2Platform` connects these to console/timer devices and AXI4-Lite memory; it requires A disabled.
`DitDahE2AtomicPlatform` requires A enabled and serializes all SRAM writers through the shared atomic endpoint, including SBA and external competitors.

```sh
make platform PLATFORM_OUTPUT=result/platform
printf '%s\n' '{"enableA":true}' > result/atomic.json
make atomic-platform CONFIG=result/atomic.json PLATFORM_OUTPUT=result/atomic
make software
```

[Integration contracts](doc/microarchitecture.md) define stage ownership, memory completion and reset behavior.
[System bus access](doc/debug-system-bus.md) describes registers, arbitration, physical addressing and debugger use.

<p align="center">
  <a href="https://github.com/vowstar/ditdah-e2/issues/1"><img src="https://github.com/user-attachments/assets/eece6547-fc38-4796-b779-99e6d22d6ff3" alt="DitDah-E2 full layout after routing and parasitic extraction" width="640"></a>
  <br><sub>Default configuration after routing and parasitic extraction. Physical signoff remains open.</sub>
</p>

## Verify

```sh
make verify-compliance
make verify-signoff
```

Signoff combines independent architectural models, protocol checks, bounded formal checks and real OpenOCD/GDB sessions.
`make verify-sba` runs SBA register, DMI, arbiter, platform and sysbus-only debugger checks; `SBA_OUTPUT` selects a fresh output directory.
`make verify-trigger-host` checks GDB hardware breakpoints; `make verify-program-host` selects Program Buffer memory access.
[Architectural tests](test/test_isa/README.md) document ISA profiles and signature comparisons. `make verify-sail` checks instruction events and signatures with the independent Sail model.

Commercial proofs have separate targets: `verify-arithmetic`, `verify-debug-commercial`, `verify-debug-abstract-commercial`, `verify-program-commercial`, `verify-trigger-commercial` and `verify-sba-commercial`.
They require licensed tools and input-bound reports. Open-source formal runs provide reference evidence; accepted commercial verdicts govern the declared proof scope.
Unit proofs, bounded core witnesses and fixed-program trigger proofs do not establish a full-core proof, complete ISA certification or physical signoff.
See [verification scope](doc/microarchitecture.md#verification-scope) and the SBA contract for assumptions and exclusions.
Reports record the selected configuration, source and RTL hashes, tools, commands and results under the chosen output directory.

## License

Project-authored files use the [MIT license](LICENSE). `REUSE.toml` records file declarations.

## Credits

DitDah-E1 and DitDah-A1 provided project organization and development conventions.
The Nix toolchain shares code with DitDah-E1.
[Zaozi](https://github.com/xinpian-tech/zaozi) provides hardware description and pinned tools.
[riscv-formal](https://github.com/YosysHQ/riscv-formal) supplies the native RVFI checkers.
[Sail RISC-V](https://github.com/riscv/sail-riscv) supplies the independent instruction model.
