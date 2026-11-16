# DitDah-E2

DitDah-E2 is a configurable 32-bit RISC-V processor for embedded control.
Its three-stage pipeline combines branch prediction, accelerated multiplication and concurrent AXI access.

<p align="center">
  <a href="https://github.com/vowstar/ditdah-e2/issues/1"><img src="https://github.com/user-attachments/assets/8af32b8f-4c40-4cd1-82a4-8c76f8294a3b" alt="DitDah-E2 layout with 16 KiB instruction SRAM and 32 KiB data SRAM" width="640"></a>
</p>

| Metric | Result |
| --- | --- |
| CoreMark workload | 2.84 iterations/s/MHz |
| TSMC 7 nm post-route STA frequency | 729.93 MHz |
| Block area, including 48 KiB SRAM | 0.03369 mm² |

Nominal STA: TT, 0.75 V, 25 °C, extracted RC, SI off. CoreMark: GCC 15.3 `-O3`, ten RTL iterations, one-cycle local SRAM.

| Instruction configuration | ISA string |
| --- | --- |
| Default | `RV32IMC_Zicntr_Zicsr_Zifencei` |
| All instruction options | `RV32IMAC_Zicntr_Zicsr_Zifencei_Zba_Zbb_Zbs` |

Use the `ilp32` ABI. For GCC, use the lowercase ISA string with `-march` and `-mabi=ilp32`.
Privilege modes, PMP and Debug are configured separately from the ISA string.

| Option | Default | Capability |
| --- | --- | --- |
| `enableM`, `enableC` | `true` | Integer multiplication/division and compressed instructions |
| `multiplyBitsPerCycle` | `4` | One, two or four iterative bits, early termination and a narrow MUL path |
| `branchPrediction` | `true` | One learned backward branch target with execution-time recovery |
| `axiConcurrent` | `true` | Two ordered AXI reads and independent write progress |
| `enableZba`, `enableZbb`, `enableZbs` | `false` | Address, basic and single-bit operations |
| `enableA` | `false` | Word LR/SC and AMOs with a shared atomic memory endpoint |
| `protectedMode` | `false` | M/U privilege modes, counter permissions and 16 PMP entries |
| `enableDebug` | `false` | Halt, resume, step, abstract register/memory access and a two-word Program Buffer |
| `enableJtag` | `false` | JTAG DTM/CDC; requires Debug and an explicit `jtagIdcode` |
| `triggerCount` | `0` | Zero or two execute-address triggers; two requires Debug |
| `enableSba` | `false` | 32-bit system bus addressing with 8/16/32-bit accesses; requires Debug |

The default privilege mode is M. Protected configurations add U; S mode and an MMU are absent. Debug supports synchronous DMI or JTAG. SBA accesses memory while the hart runs or is halted.

## Build and integrate

Enter the pinned Nix environment and generate the default SystemVerilog:

```sh
nix develop .
make rtl
```

The Nix lock pins Zaozi, CIRCT and software tools. Generated RTL and its configuration/source/tool manifest are in `result/rtl/`.
Supply options in a JSON file; `resetVector` defaults to zero and requires halfword alignment with C, otherwise word alignment.

```sh
printf '%s\n' '{"branchPrediction":false}' > result/no-prediction.json
python3 scripts/build_rtl.py --config result/no-prediction.json --output result/no-prediction-rtl
```

The core exposes separate instruction and data request/response ports, plus a separate system bus master when SBA is enabled.
`DitDahE2Platform` connects these to console/timer devices and AXI4-Lite memory; it requires A disabled.
Optional local SRAM banks share storage across instruction, data, Debug and SBA access.
`DitDahE2AtomicPlatform` requires A enabled and serializes all SRAM writers through the shared atomic endpoint, including SBA and external competitors.

```sh
make platform PLATFORM_OUTPUT=result/platform
python3 scripts/build_platform_block.py --platform-build result/platform/design --output result/block
make platform PLATFORM_MAP=platform-local.json PLATFORM_OUTPUT=result/local-platform
printf '%s\n' '{"enableA":true}' > result/atomic.json
make atomic-platform CONFIG=result/atomic.json PLATFORM_OUTPUT=result/atomic
make software
```

[Integration contracts](doc/microarchitecture.md) define stage ownership, memory completion and reset behavior. [System bus access](doc/debug-system-bus.md) covers debugger use. [Local memory](doc/local-memory.md) covers bank configuration, ROM boot and SRAM binding.
`DitDahE2PlatformBlock` exports functional integration ports and retains observation signals internally for verification.

## Verify

```sh
make verify-compliance
make verify-signoff
```

Verification combines independent instruction models, protocol checks, formal checks and OpenOCD/GDB sessions.
`make verify-axi-ordering` checks faults and FENCE.I under concurrent AXI traffic.
`make verify-sba`, `make verify-local-memory` and `make verify-local-platform` cover Debug and local memory.
[Architectural tests](test/test_isa/README.md) describe ISA profiles; `make verify-sail` checks instruction events and signatures.
[Verification scope](doc/microarchitecture.md#verification-scope) records assumptions and commercial proof targets.

## License

Project-authored files use the [MIT license](LICENSE). `REUSE.toml` records file declarations.

## Credits

DitDah-E1 and DitDah-A1 provided project organization and development conventions.
The Nix toolchain shares code with DitDah-E1.
[Zaozi](https://github.com/xinpian-tech/zaozi) provides hardware description and pinned tools.
[riscv-formal](https://github.com/YosysHQ/riscv-formal) supplies the native RVFI checkers.
[Sail RISC-V](https://github.com/riscv/sail-riscv) supplies the independent instruction model.
