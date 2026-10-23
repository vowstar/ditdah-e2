# DitDah-E2

DitDah-E2 is a three-stage RV32 processor for embedded control.
The core executes RV32I and stops on an exception.
It uses separate instruction and data ports with ordered memory completion.

## Build and verify

```sh
nix develop .
make verify-signoff
make verify-compliance
nix build .#default --no-link
```

The Nix lock pins the Zaozi and CIRCT toolchain. Nix reads Git-tracked files.

`python3 scripts/build_rtl.py --config input.json --output result/rtl` generates SystemVerilog.
The only configuration field is `resetVector`, a word-aligned unsigned 32-bit integer with a default of zero.

Use a zero `resetVector` for `verify-signoff`, `verify-formal`.
Selected checks do not establish complete ISA conformance or physical signoff.
[Integration](doc/microarchitecture.md) defines the memory and reset contracts.

## License

Project-authored files use the MIT license. `REUSE.toml` records file declarations.

## Credits

DitDah-E1 and DitDah-A1 provided project organization and development conventions.
The Nix toolchain shares code with DitDah-E1.

[Zaozi](https://github.com/xinpian-tech/zaozi) provides hardware description and pinned tools.
