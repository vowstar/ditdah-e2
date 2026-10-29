# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Exercise all word atomics through the real shared SRAM endpoint."""

from sail_program import RAM, SIGNATURE_WORDS, program


AMO_NAMES = ("amoswap", "amoadd", "amoxor", "amoand", "amoor", "amomin", "amomax", "amominu", "amomaxu")


def atomic_program(parameters):
    if not parameters["enableA"] or parameters["enableDebug"]:
        raise ValueError("Atomic Sail fixture requires A and excludes Debug intervention")
    ordinary = parameters | {"enableA": False}
    source = program(ordinary)
    initialize = ["    mv a0, s0", f"    li a1, {SIGNATURE_WORDS}", "signature_initialize:",
                  "    sw zero, 0(a0)", "    addi a0, a0, 4", "    addi a1, a1, -1",
                  "    bnez a1, signature_initialize"]
    source = source.replace("checked_start:\n", "\n".join(initialize) + "\nchecked_start:\n", 1)
    lines, offset = [f"    li a4, {RAM + 0x6000}"], 1200
    def instruction(name, text):
        lines.extend((f".globl a_case_{name}", f"a_case_{name}:", "    " + text))
    def save(register):
        nonlocal offset
        lines.append(f"    sw {register}, {offset}(s0)")
        offset += 4
    for index, suffix in enumerate(("", ".aq", ".rl", ".aqrl")):
        lines.extend((f"    li a5, {0x80000000 + index}", "    sw a5, 0(a4)", "    li a6, 0x1234567f"))
        instruction(f"lr_{index}", f"lr.w{suffix} a0, (a4)")
        instruction(f"sc_success_{index}", f"sc.w{suffix} a1, a6, (a4)")
        save("a0"); save("a1")
        lines.append("    lw a2, 0(a4)"); save("a2")
    instruction("sc_failure_no_reservation", "sc.w a1, a6, (a4)")
    save("a1")
    instruction("lr_before_store", "lr.w a0, (a4)")
    lines.append("    sw a5, 0(a4)")
    instruction("sc_failure_store", "sc.w a1, a6, (a4)")
    save("a1")
    for vector, (old, operand) in enumerate(((0x80000000, 0x7fffffff), (0x7fffffff, 0x80000000),
                                            (0, 0xffffffff), (0xffffffff, 1))):
        suffix = ("", ".aq", ".rl", ".aqrl")[vector]
        for name in AMO_NAMES:
            lines.extend((f"    li a5, {old}", "    sw a5, 0(a4)", f"    li a6, {operand}"))
            instruction(f"{name}_{vector}", f"{name}.w{suffix} a0, a6, (a4)")
            save("a0")
            lines.append("    lw a2, 0(a4)"); save("a2")
    for name in AMO_NAMES:
        instruction(f"{name}_x0", f"{name}.w zero, a6, (a4)")
        lines.append("    lw a2, 0(a4)"); save("a2")
    lines.append("    addi a4, a4, 2")
    instruction("misaligned_lr", "lr.w a0, (a4)")
    instruction("misaligned_sc", "sc.w a0, a6, (a4)")
    instruction("misaligned_amo", "amoadd.w a0, a6, (a4)")
    if offset > 2048:
        raise ValueError("Atomic observations overlap trap records")
    return source.replace("branch_taken:\n", "branch_taken:\n" + "\n".join(lines) + "\n", 1)


def observer(rtl, ram_size):
    """Expose the same physical nodes used by the platform protocol checker."""
    import re
    top = (rtl / "DitDahE2AtomicPlatformTop.sv").read_text()
    ports = re.search(r"module DitDahE2AtomicPlatformTop\((.*?)\);", top, re.S)
    if ports is None or len(re.findall(r"DitDahE2AtomicPlatform\s+platform\s*\(", top)) != 1:
        raise ValueError("Atomic platform hierarchy changed")
    declarations, assignments = [], []
    def expose(name, width, source):
        declarations.append(f"output {'[' + str(width - 1) + ':0] ' if width > 1 else ''}{name}")
        assignments.append(f"assign {name} = {source};")
    fields = {"request_valid": 1, "request_ready": 1, "request_bits_address": 32,
              "request_bits_write": 1, "request_bits_data": 32, "request_bits_mask": 4,
              "request_bits_size": 2, "request_bits_machine": 1, "request_bits_operation": 4,
              "response_valid": 1, "response_ready": 1, "response_bits_data": 32, "response_bits_fault": 1}
    for group, instance, port in (("i", "core", "instruction"), ("d", "core", "data"),
                                  ("console", "console", "memory"), ("timer", "timer", "memory")):
        for field, width in fields.items():
            expose(f"o_{group}_{field}", width, f"dut.platform.{instance}.{port}_{field}")
    for port in ("instruction", "data", "debug", "competitor"):
        for field, width in fields.items():
            expose(f"o_s_{port}_{field}", width, f"dut.platform.atomic.{port}_{field}")
    for name, source in (("reset", "shared.reset"), ("clear", "core.reservationClear"), ("debug", "core.dataDebug")):
        expose("o_" + name, 1, "dut.platform." + source)
    expose("o_halt", 1, "1'b0")
    expose("o_sram_read", 1, "dut.platform.atomic.memory.readEnable")
    width = max(1, (ram_size // 4 - 1).bit_length())
    expose("o_sram_address", 32, f"{{{32 - width}'b0, dut.platform.atomic.memory.address}}")
    expose("o_sram_mask", 4, "dut.platform.atomic.memory.writeMask")
    expose("o_sram_data", 32, "dut.platform.atomic.memory.writeData")
    # REUSE-IgnoreStart
    notice = "// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>\n// SPDX-License-Identifier: MIT\n"
    # REUSE-IgnoreEnd
    return notice + "module AtomicBench(" + ports[1] + ",\n" + ",\n".join(declarations) + ");\n" + \
        "DitDahE2AtomicPlatformTop dut(.*);\n" + "\n".join(assignments) + "\nendmodule\n"
