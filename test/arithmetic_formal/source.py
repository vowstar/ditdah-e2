# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Bind the fixed arithmetic observation source to generated processor RTL."""

import hashlib
import json
from pathlib import Path
import re

from .facts import ASSUMPTIONS, covers, goals
from .syntax import properties, tokens

HERE = Path(__file__).resolve().parent
REFERENCE_HASH = "2ae76f0ba23005d3c137781302630497ad08877654bd73536f30bda996ba5bbb"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def reference(text):
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    if len(re.findall(r"\bfunction\b", text)) != 1 or len(re.findall(r"\bendfunction\b", text)) != 1:
        raise ValueError("The architectural result function inventory changed")
    begin = text.index("    function automatic")
    end = text.index("    endfunction", begin) + len("    endfunction")
    body = text[begin:end]
    if digest(body.encode()) != REFERENCE_HASH:
        raise ValueError("The standard architectural result function changed")
    return body


def bench(operation, negative=False):
    if not 0 <= operation < 4:
        raise ValueError("Unknown arithmetic operation")
    name = "multiply.sv"
    value = (HERE / name).read_text()
    marker = '    `include "reference.svh"'
    if value.count(marker) != 1:
        raise ValueError("The standard function include is missing or duplicated")
    value = value.replace(marker, (HERE / "reference.svh").read_text())
    original = "parameter logic [2:0] OPERATION = 3'd0"
    if value.count(original) != 1:
        raise ValueError("Arithmetic operation parameter changed")
    value = value.replace(original, "parameter logic [2:0] OPERATION = 3'd" + str(operation))
    reference(value)
    labels = re.findall(r"(\w+)\s*:\s*assume\s*\(", value)
    if set(labels) != set(ASSUMPTIONS) or len(labels) != 5:
        raise ValueError("Arithmetic input assumptions differ")
    parsed = properties(value)
    goal = parsed["arithmetic_matches_reference"]
    expected = [
        {"tokens": tokens("reset"), "positive": False},
        {"tokens": tokens("cancel"), "positive": False},
        {"tokens": tokens("response_valid"), "positive": True},
        {"tokens": tokens("owner_op == OPERATION"), "positive": True},
    ]
    if goal["guards"] != expected or goal["body"] != tokens("response_bits == expected"):
        raise ValueError("The complete architectural response guard changed")
    for label, _ in goals(operation):
        if parsed.get(label, {}).get("kind") != "assert" and "." not in label:
            raise ValueError("A required native assertion is missing")
    if any(parsed.get(label, {}).get("kind") != "cover" for label in covers(operation)):
        raise ValueError("A required native cover is missing")
    if negative:
        old = "arithmetic_matches_reference: assert (response_bits == expected);"
        if value.count(old) != 1:
            raise ValueError("The result counterexample target changed")
        value = value.replace(old, "arithmetic_matches_reference: assert "
                              "(response_bits == (expected ^ 32'd1));")
    return value


def rtl(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest.get("parameters", {}).get("enableM") is not True:
        raise ValueError("Generated processor configuration does not enable M")
    path = directory / "DitDahE2MultiplyDivide.sv"
    value = path.read_bytes()
    if manifest.get("rtlHashes", {}).get(path.name) != digest(value):
        raise ValueError("Generated arithmetic RTL differs from its build manifest")
    if value.count(b"module DitDahE2MultiplyDivide(") != 1:
        raise ValueError("Unexpected arithmetic module identity")
    expected = {"clock": ("input", 1), "reset": ("input", 1),
                "cancel": ("input", 1), "request_valid": ("input", 1),
                "request_ready": ("output", 1), "request_bits_operation": ("input", 3),
                "request_bits_left": ("input", 32), "request_bits_right": ("input", 32),
                "response_valid": ("output", 1), "response_ready": ("input", 1),
                "response_bits": ("output", 32)}
    header = value.decode().split("module DitDahE2MultiplyDivide(", 1)[1].split(");", 1)[0]
    ports = {}
    direction, width = None, None
    for declaration in header.split(","):
        declaration = declaration.strip()
        new = re.fullmatch(r"(input|output)\s+(?:\[(\d+):(\d+)\]\s+)?(\w+)", declaration)
        if new:
            direction, high, low, name = new.groups()
            width = int(high) - int(low) + 1 if high else 1
        elif re.fullmatch(r"\w+", declaration) and direction:
            name = declaration
        else:
            raise ValueError("Unexpected generated arithmetic port declaration")
        if name in ports:
            raise ValueError("Duplicate arithmetic port")
        ports[name] = (direction, width)
    if ports != expected:
        raise ValueError("Arithmetic interface differs from the RV32 contract")
    return value, manifest


def source_hashes():
    return {p.name: digest(p.read_bytes()) for p in sorted(HERE.iterdir())
            if p.is_file() and p.suffix in (".py", ".sv", ".svh", ".tcl")}


def collection_hashes():
    names = ("run.py", "native.py", "facts.py", "source.py", "syntax.py", "collect.tcl", "boolean.py", "induction.sv",
             "multiply.sv", "reference.svh", "multiply_step.sv")
    return {name: digest((HERE / name).read_bytes()) for name in names}
