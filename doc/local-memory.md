<!-- SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> -->
<!-- SPDX-License-Identifier: MIT -->

# Local memory

`DitDahE2Platform` optionally connects two local memory banks alongside AXI4-Lite, console and timer devices.
The ordinary platform requires A disabled. The atomic platform retains its separate shared memory endpoint.
The default `platform.json` has no local banks.

`platform-local.json` selects 16 KiB ITCM and 32 KiB DTCM.
Both regions permit instruction reads and ordinary data reads and writes.
The names describe software placement. Data, instruction, Debug and SBA access the same physical storage for each address.
PMP checks still apply before hart memory issue. SBA supplies physical accesses independently of hart PMP permissions.

| Region field | Contract |
| --- | --- |
| `base`, `size` | Aligned RV32 byte range, disjoint from every other region |
| `readLatency` | One or two SRAM read cycles, default one |
| `backend` | `sram` for local storage, or `axi` for external memory at the same addresses |

The bank fields are optional in platform maps. A missing bank adds no corresponding ports or storage.
The supplied ROM wrapper and boot check require both banks, even though the platform accepts a single bank.
The external backend uses the external AXI timing rather than `readLatency`.
ROM remains the reset and boot source. Unmapped accesses fault without endpoint effects.
Local writes support byte, halfword and word masks with natural alignment.

## Build and boot

Run commands inside `nix develop .` and select fresh output directories.

```sh
make platform PLATFORM_MAP=platform-local.json PLATFORM_OUTPUT=result/local-platform
make verify-local-memory LOCAL_MEMORY_OUTPUT=result/local-units
make verify-local-platform LOCAL_MEMORY_OUTPUT=result/local-boot
make verify-local-sba LOCAL_MEMORY_OUTPUT=result/local-sba
```

`software/local-memory.ld` places executable sections in ITCM and writable sections and the stack in DTCM.
It includes the generated `memory.ld`. Compile payloads with the implemented ISA and the `ilp32` ABI.
The platform build writes `memory.ld` and `platform.h` to `result/local-platform/design`.
The boot check above produces the sample `result/local-boot/boot/payload/payload.elf`.
The ROM wrapper accepts a static ELF whose load segments use matching virtual and physical addresses inside those banks.

```sh
python3 scripts/build_local_software.py \
  --payload-elf result/local-boot/boot/payload/payload.elf \
  --platform platform-local.json --output result/local-software
```

The output `program.elf` loads ROM only.
Boot instructions copy each bank's used image, including segment zero-fill and intervening gaps, then execute FENCE.I and jump to the payload entry.
The payload sets its own stack and runtime state. Unused bank contents remain unspecified.
The same boot ELF can run with either backend without relocation or bank preloading.

To compare backends, reuse the executables from the boot check above:

```sh
python3 - <<'PY'
import json
from pathlib import Path
config = json.loads(Path("platform-local.json").read_text())
for name in ("itcm", "dtcm"):
    config[name]["backend"] = "axi"
Path("result/local-axi.json").write_text(json.dumps(config))
PY
python3 scripts/build_platform.py --platform result/local-axi.json --output result/local-axi
boot_check=result/local-boot/boot
python3 test/test_local_memory/platform.py --platform-build result/local-axi \
  --boot-elf "$boot_check/payload/program.elf" \
  --payload-elf "$boot_check/payload/payload.elf" --output result/local-axi-check
```

## Storage and completion

`SramParameters` defines depth, width, mask granularity and read latency independently of the byte address map.
`LocalMemory` arbitrates instruction and data requests for one bank using round-robin grants.
Different banks operate independently. Each port retains its accepted owner until its response completes.
Held requests and responses remain stable through backpressure. A consumed response can release capacity for the next request on the same edge.
With both requesters eligible, grants alternate as transactions complete. Infinite downstream stalls provide no finite cycle bound.

The behavioral primitive samples the previous word on a simultaneous read and masked write.
Disabled reads hold the last output. A pending two-cycle read still finishes before its output holds.
Storage has no reset. Platform warm-reset sequencing drains offered and accepted transactions before resetting controller state.
Boot copying can overwrite previously stored data after reset.

`AtomicSram` uses the common primitive.
`AtomicMemory` waits for the selected read latency before AMO computation and writeback.
Atomic reservation changes remain serialized across all writers by the atomic endpoint.

## Functional block interface

`DitDahE2PlatformBlock` exports the platform inputs, AXI, console transmit, sleeping status and enabled Debug transport.
Retirement and execution observation outputs stay internal.
The derived build preserves the original platform RTL and records its manifest hash.

```sh
python3 scripts/build_platform_block.py --platform-build result/local-platform/design --output result/local-block
```

The platform verification harness can observe the internal signals while instantiating this block.
Memory macro selection remains a separate technology binding.

The supplied storage is synthesizable behavioral RTL.
A technology SRAM binding requires matching masks, latency, collision semantics, timing and physical views.
No particular memory macro, area or operating frequency follows from RTL simulation.

## Verification

`verify-local-memory` checks the controller with an independent byte-memory model across bank sizes and read latencies.
`verify-local-platform` executes ROM boot, local code updates with FENCE.I, data-bank execution and MMIO against the independent instruction model.
Its harness initializes ROM only and rejects external AXI access to locally selected banks.
`make verify-signoff` includes the controller and ROM-boot checks, using an A-disabled local configuration independent of `CONFIG`.
`LOCAL_MEMORY_CONFIG` supplies optional core settings for the local boot check.
`verify-local-sba` checks hart/SBA visibility and concurrent local execution.
Its reset case drains a delayed external SBA read while local code runs and checks that bank contents survive.
