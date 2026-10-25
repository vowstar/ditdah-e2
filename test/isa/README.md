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

For the ordinary adapter, keep `enableA`, `enableDebug`, `protectedMode` false.
