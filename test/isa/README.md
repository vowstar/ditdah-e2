<!-- SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> -->
<!-- SPDX-License-Identifier: MIT -->

# Architectural tests

Compare RTL signatures with Spike using the same ELF. These selected tests do not establish complete ISA or privilege conformance.
Generate RTL with reset address `0x80000000`. Test RAM occupies four MiB at that address.
Run these commands in `nix develop .`.

```sh
work=$(mktemp -d)
printf '%s\n' '{"resetVector":2147483648}' > "$work/reset.json"
python3 scripts/build_rtl.py --config "$work/reset.json" --output result/isa-rtl
bash test/isa/run.sh --rtl result/isa-rtl --source-root . --suite rv32i
rm -r "$work"
```

Use a new `--output` directory for each run. Sources and versions are pinned in [isa-tools.nix](../../nix/isa-tools.nix).

| Suite | RTL configuration |
| --- | --- |
| `add`, `rv32i` | Default ADD test or the RV32I collection |
| `rv32m`, `rv32c` | Enable M or C respectively |
| `rv32zba`, `rv32zbb`, `rv32zbs`, `rv32b` | Enable the selected bit extension, or all three for `rv32b` |
| `machine-exceptions`, `ecall` | Disable M and C |
| `cebreak` | Enable C |

For the ordinary adapter, keep `enableA`, `enableDebug`, `protectedMode` false.

B tests skip the upstream assertion hook because its ANDN constant is incorrect. Signature and retirement checks remain enabled.

## AMO tests

Copy `platform.json` to `atomic-platform.json`. Set ROM base to `2147483648` and size to `4194304`. Keep other regions unchanged.
Save this configuration as `atomic-core.json`.

```json
{"resetVector":2147483648,"enableM":false,"enableC":false,"enableA":true}
```

```sh
python3 scripts/build_atomic_platform.py --platform atomic-platform.json --config atomic-core.json --output result/isa-atomic-design
bash test/isa/atomic.sh --design result/isa-atomic-design --output result/isa-atomic-signatures
```

A selected subset must include `--test amoadd.w` for the RTL fault check.
These official tests exclude LR/SC and acquire/release variants.

## Protected workload

Copy `platform.json` to `platform-reference.json`. Set ROM to `0x80000000` and console to `0x30000000`, preserving region sizes and other addresses.
Save this configuration as `protected-reference.json`. Keep debug, A and bit extensions disabled.

```json
{"resetVector":2147483648,"enableM":true,"enableC":true,"protectedMode":true}
```

```sh
python3 scripts/build_platform.py --platform platform-reference.json --config protected-reference.json --output result/protected-reference-design
python3 test/verify_platform.py --platform result/protected-reference-design --workload protected --output result/protected-reference-platform
bash test/isa/protected.sh --verification result/protected-reference-platform --output result/protected-reference
```

Keep the platform verification output with the reference report.

Use `make verify-isa-menvcfg` for environment CSR checks and a new `ISA_MENVCFG_OUTPUT` directory for each run.
