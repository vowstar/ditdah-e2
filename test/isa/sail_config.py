# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Map an explicit E2 profile to the reviewed Sail 0.12 configuration."""

import copy
import json


PARAMETERS = {"resetVector", "enableM", "enableC", "protectedMode", "enableDebug", "enableA",
              "enableZba", "enableZbb", "enableZbs"}
ALIGNMENT = {"load_store": {"Some": "AlignmentException"},
             "vector": {"Some": "AlignmentException"},
             "lrsc": "AlignmentException", "amo": "AlignmentException"}


def parse_defaults(text):
    """Accept the pinned default printer's whole-line comments and ordinary JSON."""
    filtered = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
    value = json.loads(filtered)
    if not isinstance(value, dict) or value.get("base", {}).get("xlen") != 32:
        raise ValueError("Expected native RV32 configuration defaults")
    return value


def _disable(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "supported":
                value[key] = False
            else:
                _disable(item)
    elif isinstance(value, list):
        for item in value:
            _disable(item)


def configuration(defaults, parameters, regions, *, instruction_limit):
    """Return a fresh configuration; validate it with the real model before use."""
    if set(parameters) != PARAMETERS:
        raise ValueError("Core parameter fields differ")
    if any(type(parameters[key]) is not bool for key in PARAMETERS - {"resetVector"}):
        raise ValueError("Core feature parameters must be booleans")
    reset = parameters["resetVector"]
    if type(reset) is not int or not 0 <= reset <= 0xffffffff or reset % (2 if parameters["enableC"] else 4):
        raise ValueError("Reset vector does not satisfy RV32 instruction alignment")
    if parameters["enableDebug"]:
        raise ValueError("The standalone Sail profile excludes Debug intervention")
    if type(instruction_limit) is not int or not 0 < instruction_limit < (1 << 32):
        raise ValueError("A positive bounded instruction limit is required")
    result = copy.deepcopy(defaults)
    if result.get("base", {}).get("xlen") != 32:
        raise ValueError("Expected RV32 defaults")
    extensions = result["extensions"]
    _disable(extensions)
    selected = {"Zicsr", "Zifencei", "Zicntr"}
    for parameter, extension in [("enableM", "M"), ("enableC", "Zca"), ("protectedMode", "U"),
                                 ("enableA", "A"), ("enableZba", "Zba"),
                                 ("enableZbb", "Zbb"), ("enableZbs", "Zbs")]:
        if parameters[parameter]:
            selected.add(extension)
    if all(parameters[key] for key in ("enableZba", "enableZbb", "enableZbs")):
        selected.add("B")
    for extension in selected:
        extensions[extension]["supported"] = True
    extensions["V"]["support_level"] = "Disabled"
    result["base"].update({"E": False, "writable_misa": False, "writable_fiom": False,
                           "writable_hpm_counters": {"len": 32, "value": "0x0"},
                           "mcounteren_writable_bits": {"len": 32, "value": "0x7"},
                           "scounteren_writable_bits": {"len": 32, "value": "0x0"}})
    result["base"]["mstatus"].update({"fs_legal_states": "ExtContext_Off", "vs_legal_states": "ExtContext_Off"})
    count = 16 if parameters["protectedMode"] else 0
    result["memory"]["pmp"].update({"count": count, "usable_count": count, "grain": 0,
                                      "tor_supported": True, "na4_supported": True, "napot_supported": True})
    result["memory"]["misaligned"]["exceptions"] = copy.deepcopy(ALIGNMENT)
    if not regions:
        raise ValueError("At least one explicit program memory region is required")
    main = next(region for region in result["memory"]["regions"]
                if region["attributes"]["mem_type"] == "MainMemory")
    io = copy.deepcopy(next(region for region in result["memory"]["regions"]
                            if region["attributes"]["mem_type"] == "IOMemory"))
    normalized = []
    for region in regions:
        if set(region) != {"base", "size", "read", "write", "execute", "atomic"}:
            raise ValueError("Memory region fields differ")
        base, size = region["base"], region["size"]
        if type(base) is not int or type(size) is not int or base < 0 or size <= 0 or base + size > 1 << 32:
            raise ValueError("Invalid RV32 memory region")
        if any(type(region[key]) is not bool for key in ("read", "write", "execute", "atomic")):
            raise ValueError("Memory permissions must be booleans")
        item = copy.deepcopy(main if region["read"] and region["write"] else io)
        item.update({"base": {"len": 64, "value": hex(base)}, "size": {"len": 64, "value": hex(size)},
                     "include_in_device_tree": False})
        attributes = item["attributes"]
        attributes.update({"readable": region["read"], "writable": region["write"],
                           "executable": region["execute"], "supports_cbo_zero": False,
                           "read_idempotent": True, "write_idempotent": True,
                           "supports_pte_read": False, "supports_pte_write": False,
                           "misaligned_exceptions": {key: copy.deepcopy(value) for key, value in ALIGNMENT.items()
                                                      if key != "lrsc"},
                           "atomic_support": "AMOCASQ" if region["atomic"] else "AMONone",
                           "reservability": "RsrvEventual" if region["atomic"] else "RsrvNone"})
        normalized.append(item)
    dtb = 0xfffff000
    io.update({"base": {"len": 64, "value": hex(dtb)}, "size": {"len": 64, "value": "0x1000"},
               "include_in_device_tree": False})
    normalized.append(io)
    normalized.sort(key=lambda region: int(region["base"]["value"], 16))
    for first, second in zip(normalized, normalized[1:]):
        if int(first["base"]["value"], 16) + int(first["size"]["value"], 16) > int(second["base"]["value"], 16):
            raise ValueError("Memory or harness DTB regions overlap")
    result["memory"]["regions"] = normalized
    result["memory"]["dtb_address"] = {"len": 64, "value": hex(dtb)}
    result["platform"]["clint"]["supported"] = False
    result["platform"]["simple_interrupt_generator"]["supported"] = False
    result["platform"]["instructions_per_tick"] = instruction_limit + 1
    result["platform"]["wfi_is_nop"] = True
    result["platform"]["reservation"].update({"reservation_set_size_exp": 2,
                                             "require_exact_reservation_addr": True,
                                             "invalidate_on_same_hart_store": True})
    return result
