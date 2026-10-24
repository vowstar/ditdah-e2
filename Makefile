# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

export PYTHONDONTWRITEBYTECODE = 1
CONFIG ?=

.PHONY: rtl software verify-signoff verify-formal verify-software verify-axi verify-isa verify-isa-m verify-isa-c verify-multiply verify-timer verify-compliance
rtl:
	python3 scripts/build_rtl.py $(if $(CONFIG),--config "$(CONFIG)")

software:
	python3 scripts/build_software.py

verify-software: rtl
	python3 test/verify_software.py

verify-axi:
	python3 test/axi.py
	python3 test/axi_formal.py --rtl result/axi

verify-multiply:
	python3 test/multiply_divide_formal.py

verify-timer:
	python3 test/timer.py

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

verify-signoff: rtl
	python3 test/verify.py
	python3 test/formal.py
	python3 test/core_formal.py

verify-formal: rtl
	python3 test/formal.py
	python3 test/core_formal.py

verify-compliance:
	python3 -m unittest discover -s test -p 'test_*.py'
	python3 -m unittest discover -s test/isa -p 'test_*.py'
	reuse lint
