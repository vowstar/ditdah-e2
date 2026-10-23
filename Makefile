# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

export PYTHONDONTWRITEBYTECODE = 1

.PHONY: rtl verify-signoff verify-formal verify-compliance
rtl:
	python3 scripts/build_rtl.py

verify-signoff: rtl
	python3 test/verify.py
	python3 test/formal.py

verify-formal: rtl
	python3 test/formal.py

verify-compliance:
	python3 -m unittest discover -s test -p 'test_*.py'
	reuse lint
