# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

export PYTHONDONTWRITEBYTECODE = 1
CONFIG ?=
PLATFORM_OUTPUT ?= result/platform

DEBUG_LATENCY_OUTPUT ?= result/debug-latency

INTERRUPT_OUTPUT ?= result/interrupt-stress

.PHONY: rtl platform software verify-signoff verify-formal verify-throughput verify-software verify-platform verify-router verify-axi verify-isa verify-isa-m verify-isa-c verify-multiply verify-timer verify-console verify-protection verify-pmp verify-compliance verify-debug-formal verify-debug-latency verify-atomic-formal verify-interrupts
rtl:
	python3 scripts/build_rtl.py $(if $(CONFIG),--config "$(CONFIG)")

platform:
	python3 scripts/build_platform.py $(if $(CONFIG),--config "$(CONFIG)") --output "$(PLATFORM_OUTPUT)/design"

software:
	python3 scripts/build_software.py

verify-software: rtl
	python3 test/verify_software.py

verify-platform: platform
	python3 test/verify_platform.py --platform "$(PLATFORM_OUTPUT)/design" --output "$(PLATFORM_OUTPUT)/verification"

verify-router: platform
	python3 test/router.py --platform-build "$(PLATFORM_OUTPUT)/design" --output "$(PLATFORM_OUTPUT)/router"

verify-axi:
	python3 test/axi.py
	python3 test/axi_formal.py --rtl result/axi

verify-multiply:
	python3 test/multiply_divide_formal.py

verify-timer:
	python3 test/timer.py

verify-console:
	python3 test/console.py

verify-isa:
	mkdir -p result
	printf '%s\n' '{"resetVector":2147483648,"enableM":false,"enableC":false}' > result/isa-reset.json
	python3 scripts/build_rtl.py --config result/isa-reset.json --output result/isa-rtl
	bash test/isa/run.sh --rtl result/isa-rtl --source-root . --suite rv32i

verify-isa-m:
	mkdir -p result
	printf '%s\n' '{"resetVector":2147483648,"enableM":true,"enableC":false}' > result/isa-m-reset.json
	python3 scripts/build_rtl.py --config result/isa-m-reset.json --output result/isa-m-rtl
	bash test/isa/run.sh --rtl result/isa-m-rtl --source-root . --suite rv32m

verify-isa-c:
	mkdir -p result
	printf '%s\n' '{"resetVector":2147483648,"enableM":false,"enableC":true}' > result/isa-c-reset.json
	python3 scripts/build_rtl.py --config result/isa-c-reset.json --output result/isa-c-rtl
	bash test/isa/run.sh --rtl result/isa-c-rtl --source-root . --suite rv32c

verify-protection:
	python3 test/protection_port.py
	python3 test/protection_formal.py --rtl result/protection-port --output result/protection-formal

verify-pmp:
	python3 test/pmp.py

verify-signoff: rtl
	python3 test/verify.py
	python3 test/formal.py
	python3 test/core_formal.py

verify-formal: rtl
	python3 test/formal.py
	python3 test/core_formal.py

verify-throughput: rtl
	python3 test/fetch_throughput.py

verify-compliance:
	python3 -m unittest discover -s test -p 'test_*.py'
	python3 -m unittest discover -s test/isa -p 'test_*.py'
	reuse lint

verify-debug-formal:
	mkdir -p result
	printf '%s\n' '{"enableM":false,"enableC":false,"enableDebug":true}' > result/debug-formal.json
	python3 scripts/build_rtl.py --config result/debug-formal.json --output result/debug-formal-rtl
	python3 test/debug_core_formal.py --rtl result/debug-formal-rtl --output result/debug-core-formal

verify-debug-latency:
	mkdir -p "$(DEBUG_LATENCY_OUTPUT)"
	printf '%s\n' '{"enableM":true,"enableC":true,"enableDebug":true}' > "$(DEBUG_LATENCY_OUTPUT)/configuration.json"
	python3 scripts/build_rtl.py --config "$(DEBUG_LATENCY_OUTPUT)/configuration.json" --output "$(DEBUG_LATENCY_OUTPUT)/design"
	python3 test/debug_latency_formal.py --rtl "$(DEBUG_LATENCY_OUTPUT)/design" --output "$(DEBUG_LATENCY_OUTPUT)/control" --depth 192 --timeout 1800 --case safety --case halt-blocked --case resume-blocked
	python3 test/debug_latency_formal.py --rtl "$(DEBUG_LATENCY_OUTPUT)/design" --output "$(DEBUG_LATENCY_OUTPUT)/step" --depth 384 --timeout 1800 \
		--case step-safety --case payload --case step-payload --case complete --case instruction-accepted \
		--case data-accepted --case instruction-offered --case data-offered --case step-retire --case step-trap \
		--case step-memory --case step-multiply --case step-crossing --case extra-step

verify-atomic-formal:
	mkdir -p result
	printf '%s\n' '{"baseAddress":0,"sizeBytes":16}' > result/atomic-small.json
	python3 test/atomic_memory.py --config result/atomic-small.json --output result/atomic-small
	python3 test/atomic_memory_formal.py --rtl result/atomic-small --output result/atomic-formal

verify-interrupts: rtl
	python3 test/interrupt_stress.py --rtl result/rtl --output "$(INTERRUPT_OUTPUT)"
