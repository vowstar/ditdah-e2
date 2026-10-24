# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

export PYTHONDONTWRITEBYTECODE = 1

.PHONY: rtl software verify-signoff verify-formal verify-software verify-axi verify-isa verify-compliance
rtl:
	python3 scripts/build_rtl.py

software:
	python3 scripts/build_software.py

verify-software: rtl
	python3 test/verify_software.py

verify-axi:
	python3 test/axi.py
	python3 test/axi_formal.py --rtl result/axi

verify-isa:
	mkdir -p result
	printf '%s\n' '{"resetVector":2147483648}' > result/isa-reset.json
	python3 scripts/build_rtl.py --config result/isa-reset.json --output result/isa-rtl
	bash test/isa/run.sh --rtl result/isa-rtl --source-root . --suite rv32i

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
