# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

export PYTHONDONTWRITEBYTECODE = 1
CONFIG ?=
PLATFORM_OUTPUT ?= result/platform
GENERIC_OUTPUT ?= result/generic
DEBUG_LATENCY_OUTPUT ?= result/debug-latency
ISA_MENVCFG_OUTPUT ?= result/isa-menvcfg
PMP_DATA_OUTPUT ?= result/pmp-data
INTERRUPT_OUTPUT ?= result/interrupt-stress
FETCH_PERFORMANCE_OUTPUT ?= result/fetch-performance
FETCH_PERFORMANCE_ARGS ?=
RVFI_RTL ?= result/rtl
RVFI_OUTPUT ?= result/rvfi
RVFI_ARGS ?=
SAIL_PROFILES ?= imc=result/isa-rtl
SAIL_OUTPUT ?= result/sail
ARITHMETIC_RTL ?= result/rtl
ARITHMETIC_OUTPUT ?= result/arithmetic
ARITHMETIC_ARGS ?=
JTAG_OUTPUT ?= result/jtag-transport-verification
JTAG_CORE_OUTPUT ?= result/jtag-core
DEBUG_HOST_OUTPUT ?= result/jtag-host
DEBUG_HOST_BASELINE ?=
JTAG_IDCODE ?= 3791650817
DEBUG_TRANSPORT_OUTPUT ?= result/debug-transport-commercial
DEBUG_TRANSPORT_JG_ARGS ?=
DEBUG_MODULE_OUTPUT ?= result/debug-module
DEBUG_ABSTRACT_OUTPUT ?= result/debug-abstract-commercial
DEBUG_ABSTRACT_JG_ARGS ?=

.PHONY: rtl platform atomic-platform software verify-signoff verify-formal verify-throughput verify-fetch-performance verify-generic verify-software verify-platform verify-router verify-axi verify-isa verify-isa-m verify-isa-c verify-isa-bit verify-isa-menvcfg verify-multiply verify-bit verify-debug verify-debug-module verify-jtag verify-debug-host verify-debug-commercial verify-debug-abstract-commercial verify-debug-formal verify-debug-latency verify-atomic verify-atomic-memory verify-atomic-formal verify-timer verify-console verify-protection verify-pmp verify-pmp-data verify-interrupts verify-compliance
rtl:
	python3 scripts/build_rtl.py $(if $(CONFIG),--config "$(CONFIG)")

platform:
	python3 scripts/build_platform.py $(if $(CONFIG),--config "$(CONFIG)") --output "$(PLATFORM_OUTPUT)/design"

atomic-platform:
	python3 scripts/build_atomic_platform.py $(if $(CONFIG),--config "$(CONFIG)") --output "$(PLATFORM_OUTPUT)/design"

software:
	python3 scripts/build_software.py

verify-software: rtl
	python3 test/test_software/verify_software.py

verify-platform: platform
	python3 test/test_platform/verify_platform.py --platform "$(PLATFORM_OUTPUT)/design" --output "$(PLATFORM_OUTPUT)/verification"

verify-router: platform
	python3 test/test_platform/router.py --platform-build "$(PLATFORM_OUTPUT)/design" --output "$(PLATFORM_OUTPUT)/router"

verify-axi:
	python3 test/test_platform/axi.py
	python3 formal/axi/axi_formal.py --rtl result/axi

verify-multiply:
	python3 formal/arithmetic/multiply_divide_formal.py

.PHONY: verify-arithmetic
verify-arithmetic:
	python3 formal/arithmetic/run.py prepare --rtl "$(ARITHMETIC_RTL)" --output "$(ARITHMETIC_OUTPUT)/evidence" $(ARITHMETIC_ARGS)
	python3 formal/arithmetic/run.py collect --evidence "$(ARITHMETIC_OUTPUT)/evidence" --private-output "$(ARITHMETIC_OUTPUT)/native-private" $(ARITHMETIC_ARGS)
	python3 formal/arithmetic/run.py replay --evidence "$(ARITHMETIC_OUTPUT)/evidence" --output "$(ARITHMETIC_OUTPUT)/replay"

verify-bit:
	python3 test/units/bit_operations.py

verify-debug: rtl
	python3 test/test_debug/verify_debug.py --rtl result/rtl --output result/debug-verification

verify-debug-module:
	python3 test/test_debug/debug_module.py --output "$(DEBUG_MODULE_OUTPUT)"

verify-jtag:
	python3 test/test_jtag/verify_jtag.py --output "$(JTAG_OUTPUT)"

verify-debug-host:
	mkdir -p "$(JTAG_CORE_OUTPUT)"
	printf '%s\n' '{"enableDebug":true,"enableJtag":true,"jtagIdcode":$(JTAG_IDCODE)}' > "$(JTAG_CORE_OUTPUT)/input.json"
	python3 scripts/build_rtl.py --config "$(JTAG_CORE_OUTPUT)/input.json" --output "$(JTAG_CORE_OUTPUT)/design"
	python3 test/test_debug_host/verify_host.py --rtl "$(JTAG_CORE_OUTPUT)/design" --output "$(DEBUG_HOST_OUTPUT)" $(if $(DEBUG_HOST_BASELINE),--baseline "$(DEBUG_HOST_BASELINE)")

verify-debug-commercial:
	mkdir -p "$(DEBUG_TRANSPORT_OUTPUT)"
	printf '%s\n' '{"enableDebug":false,"enableJtag":false}' > "$(DEBUG_TRANSPORT_OUTPUT)/input.json"
	python3 scripts/build_rtl.py --top DitDahE2DmiBridge --config "$(DEBUG_TRANSPORT_OUTPUT)/input.json" --output "$(DEBUG_TRANSPORT_OUTPUT)/bridge"
	hash=$$(python3 -c 'import hashlib; print(hashlib.sha256(open("$(DEBUG_TRANSPORT_OUTPUT)/bridge/DitDahE2DmiBridge.sv","rb").read()).hexdigest())'); \
	python3 -m formal.debug_transport.run prepare --rtl "$(DEBUG_TRANSPORT_OUTPUT)/bridge" --source-root . --expected-rtl-sha256 "$$hash" --output "$(DEBUG_TRANSPORT_OUTPUT)/evidence"
	python3 -m formal.debug_transport.run collect --evidence "$(DEBUG_TRANSPORT_OUTPUT)/evidence" --private-output "$(DEBUG_TRANSPORT_OUTPUT)/native-private" $(DEBUG_TRANSPORT_JG_ARGS)
	python3 -m formal.debug_transport.run validate --evidence "$(DEBUG_TRANSPORT_OUTPUT)/evidence"

verify-debug-abstract-commercial:
	mkdir -p "$(DEBUG_ABSTRACT_OUTPUT)"
	printf '%s\n' '{"enableDebug":true,"enableJtag":false}' > "$(DEBUG_ABSTRACT_OUTPUT)/input.json"
	python3 scripts/build_rtl.py --top DitDahE2DebugModule --config "$(DEBUG_ABSTRACT_OUTPUT)/input.json" --output "$(DEBUG_ABSTRACT_OUTPUT)/rtl"
	hash=$$(python3 -c 'import hashlib; print(hashlib.sha256(open("$(DEBUG_ABSTRACT_OUTPUT)/rtl/DitDahE2DebugModule.sv","rb").read()).hexdigest())'); \
	python3 -m formal.debug_abstract.run prepare --rtl "$(DEBUG_ABSTRACT_OUTPUT)/rtl" --source-root . --expected-rtl-sha256 "$$hash" --output "$(DEBUG_ABSTRACT_OUTPUT)/evidence"
	python3 -m formal.debug_abstract.run collect --evidence "$(DEBUG_ABSTRACT_OUTPUT)/evidence" --private-output "$(DEBUG_ABSTRACT_OUTPUT)/native-private" $(DEBUG_ABSTRACT_JG_ARGS)
	python3 -m formal.debug_abstract.run validate --evidence "$(DEBUG_ABSTRACT_OUTPUT)/evidence"

verify-debug-formal:
	mkdir -p result
	printf '%s\n' '{"enableM":false,"enableC":false,"enableDebug":true}' > result/debug-formal.json
	python3 scripts/build_rtl.py --config result/debug-formal.json --output result/debug-formal-rtl
	python3 formal/debug/debug_core_formal.py --rtl result/debug-formal-rtl --output result/debug-core-formal

verify-debug-latency:
	mkdir -p "$(DEBUG_LATENCY_OUTPUT)"
	printf '%s\n' '{"enableM":true,"enableC":true,"enableDebug":true}' > "$(DEBUG_LATENCY_OUTPUT)/configuration.json"
	python3 scripts/build_rtl.py --config "$(DEBUG_LATENCY_OUTPUT)/configuration.json" --output "$(DEBUG_LATENCY_OUTPUT)/design"
	python3 formal/debug/debug_latency_formal.py --rtl "$(DEBUG_LATENCY_OUTPUT)/design" --output "$(DEBUG_LATENCY_OUTPUT)/control" --depth 192 --timeout 1800 --case safety --case halt-blocked --case resume-blocked
	python3 formal/debug/debug_latency_formal.py --rtl "$(DEBUG_LATENCY_OUTPUT)/design" --output "$(DEBUG_LATENCY_OUTPUT)/step" --depth 384 --timeout 1800 \
		--case step-safety --case payload --case step-payload --case complete --case instruction-accepted \
		--case data-accepted --case instruction-offered --case data-offered --case step-retire --case step-trap \
		--case step-memory --case step-multiply --case step-crossing --case extra-step

verify-atomic: atomic-platform
	python3 test/test_atomic/verify_atomic.py --design "$(PLATFORM_OUTPUT)/design" --output "$(PLATFORM_OUTPUT)/verification"

verify-atomic-memory:
	python3 test/units/atomic_memory.py

verify-atomic-formal:
	mkdir -p result
	printf '%s\n' '{"baseAddress":0,"sizeBytes":16}' > result/atomic-small.json
	python3 test/units/atomic_memory.py --config result/atomic-small.json --output result/atomic-small
	python3 formal/atomic/atomic_memory_formal.py --rtl result/atomic-small --output result/atomic-formal

verify-timer:
	python3 test/test_platform/timer.py

verify-console:
	python3 test/test_platform/console.py

verify-isa:
	mkdir -p result
	printf '%s\n' '{"resetVector":2147483648,"enableM":false,"enableC":false}' > result/isa-reset.json
	python3 scripts/build_rtl.py --config result/isa-reset.json --output result/isa-rtl
	bash test/test_isa/run.sh --rtl result/isa-rtl --source-root . --suite rv32i

verify-isa-m:
	mkdir -p result
	printf '%s\n' '{"resetVector":2147483648,"enableM":true,"enableC":false}' > result/isa-m-reset.json
	python3 scripts/build_rtl.py --config result/isa-m-reset.json --output result/isa-m-rtl
	bash test/test_isa/run.sh --rtl result/isa-m-rtl --source-root . --suite rv32m

verify-isa-c:
	mkdir -p result
	printf '%s\n' '{"resetVector":2147483648,"enableM":false,"enableC":true}' > result/isa-c-reset.json
	python3 scripts/build_rtl.py --config result/isa-c-reset.json --output result/isa-c-rtl
	bash test/test_isa/run.sh --rtl result/isa-c-rtl --source-root . --suite rv32c

verify-isa-bit:
	mkdir -p result
	printf '%s\n' '{"resetVector":2147483648,"enableM":false,"enableC":false,"enableZba":true,"enableZbb":true,"enableZbs":true}' > result/isa-bit-reset.json
	python3 scripts/build_rtl.py --config result/isa-bit-reset.json --output result/isa-bit-rtl
	bash test/test_isa/run.sh --rtl result/isa-bit-rtl --source-root . --suite rv32b

verify-isa-menvcfg:
	mkdir -p "$(ISA_MENVCFG_OUTPUT)"
	printf '%s\n' '{"resetVector":2147483648,"enableM":false,"enableC":false,"protectedMode":true}' > "$(ISA_MENVCFG_OUTPUT)/minimal.json"
	printf '%s\n' '{"resetVector":2147483648,"enableM":true,"enableC":true}' > "$(ISA_MENVCFG_OUTPUT)/machine.json"
	python3 scripts/build_rtl.py --config "$(ISA_MENVCFG_OUTPUT)/minimal.json" --output "$(ISA_MENVCFG_OUTPUT)/minimal-rtl"
	python3 scripts/build_rtl.py --config "$(ISA_MENVCFG_OUTPUT)/machine.json" --output "$(ISA_MENVCFG_OUTPUT)/machine-rtl"
	bash test/test_isa/menvcfg.sh --profile "minimal=$(ISA_MENVCFG_OUTPUT)/minimal-rtl" --profile "machine=$(ISA_MENVCFG_OUTPUT)/machine-rtl" --output "$(ISA_MENVCFG_OUTPUT)/low"
	bash test/test_isa/menvcfg.sh --profile "minimal=$(ISA_MENVCFG_OUTPUT)/minimal-rtl" --profile "machine=$(ISA_MENVCFG_OUTPUT)/machine-rtl" --csr-address 0x31a --output "$(ISA_MENVCFG_OUTPUT)/high"

verify-protection:
	python3 test/units/protection_port.py
	python3 formal/protection/protection_formal.py --rtl result/protection-port --output result/protection-formal

verify-pmp:
	python3 test/units/pmp.py

verify-interrupts: rtl
	python3 test/test_ditdah_e2/interrupt_stress.py --rtl result/rtl --output "$(INTERRUPT_OUTPUT)"

verify-pmp-data:
	mkdir -p "$(PMP_DATA_OUTPUT)"
	printf '%s\n' '{"enableM":false,"enableC":false,"protectedMode":true}' > "$(PMP_DATA_OUTPUT)/configuration.json"
	python3 scripts/build_rtl.py --config "$(PMP_DATA_OUTPUT)/configuration.json" --output "$(PMP_DATA_OUTPUT)/rtl"
	python3 formal/protection/pmp_data_formal.py --rtl "$(PMP_DATA_OUTPUT)/rtl" --source-root . --output "$(PMP_DATA_OUTPUT)/proof"

verify-signoff: rtl verify-jtag verify-debug-host verify-debug-module
	python3 test/test_ditdah_e2/verify.py --rvfi
	python3 formal/core/formal.py
	python3 formal/core/core_formal.py

.PHONY: verify-retirement verify-rvfi verify-sail
verify-retirement: rtl
	python3 test/test_ditdah_e2/verify.py --rvfi

verify-rvfi:
	bash formal/riscv_formal/rvfi.sh --rtl "$(RVFI_RTL)" --output "$(RVFI_OUTPUT)" $(RVFI_ARGS)

verify-sail:
	bash test/test_sail/sail.sh $(foreach profile,$(SAIL_PROFILES),--profile "$(profile)") --output "$(SAIL_OUTPUT)"

verify-formal: rtl
	python3 formal/core/formal.py
	python3 formal/core/core_formal.py

verify-throughput: rtl
	python3 test/test_benchmark/fetch_throughput.py

verify-fetch-performance: rtl platform
	python3 test/test_benchmark/fetch_performance.py --current-core result/rtl --current-platform "$(PLATFORM_OUTPUT)/design" --output "$(FETCH_PERFORMANCE_OUTPUT)" $(FETCH_PERFORMANCE_ARGS)

verify-generic: rtl
	python3 scripts/synthesize.py --rtl result/rtl --output "$(GENERIC_OUTPUT)/synthesis"
	python3 test/test_ditdah_e2/generic_netlist.py --synthesis "$(GENERIC_OUTPUT)/synthesis" --output "$(GENERIC_OUTPUT)/execution"

verify-compliance:
	python3 -m unittest discover -s test -p 'test_*.py'
	reuse lint
