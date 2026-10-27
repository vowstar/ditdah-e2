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
| `machine-exceptions`, `ecall` | Disable M and C |
| `cebreak` | Enable C |

For the ordinary adapter, keep `enableA`, `enableDebug`, `protectedMode` false.

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
