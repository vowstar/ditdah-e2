# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Original bounded ELF fixture shared by the RTL and Sail runners."""


RAM = 0x20000000
RAM_SIZE = 0x10000
SIGNATURE_WORDS = 1024
TRAP_OFFSET = 2048


def bit_encodings():
    """Enumerate the implemented RV32 bit instruction forms from their ISA fields."""
    result = []
    def register(name, group, function, subfunction, second=16):
        result.append((name, group, function << 25 | second << 20 | 31 << 15 |
                       subfunction << 12 | 10 << 7 | 0x33))
    def immediate(name, group, immediate, subfunction):
        result.append((name, group, immediate << 20 | 31 << 15 | subfunction << 12 | 10 << 7 | 0x13))
    for name, function in (("sh1add", 2), ("sh2add", 4), ("sh3add", 6)):
        register(name, "Zba", 0x10, function)
    for name, function in (("andn", 7), ("orn", 6), ("xnor", 4)):
        register(name, "Zbb", 0x20, function)
    for name, code in (("clz", 0x600), ("ctz", 0x601), ("cpop", 0x602),
                       ("sext_b", 0x604), ("sext_h", 0x605)):
        immediate(name, "Zbb", code, 1)
    for name, function in (("max", 6), ("maxu", 7), ("min", 4), ("minu", 5)):
        register(name, "Zbb", 5, function)
    register("zext_h", "Zbb", 4, 4, 0)
    register("rol", "Zbb", 0x30, 1)
    register("ror", "Zbb", 0x30, 5)
    immediate("rori", "Zbb", 0x600 | 31, 5)
    immediate("orc_b", "Zbb", 0x287, 5)
    immediate("rev8", "Zbb", 0x698, 5)
    for name, function, subfunction in (("bclr", 0x24, 1), ("bext", 0x24, 5),
                                        ("binv", 0x34, 1), ("bset", 0x14, 1)):
        register(name, "Zbs", function, subfunction)
        immediate(name + "i", "Zbs", function << 5 | 31, subfunction)
    return result

# REUSE-IgnoreStart
NOTICE = """/* SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com> */
/* SPDX-License-Identifier: MIT */
"""
# REUSE-IgnoreEnd


def program(parameters):
    if parameters["enableA"] or parameters["enableDebug"]:
        raise ValueError("This fixture requires the ordinary memory endpoint without Debug")
    reset = parameters["resetVector"]
    if reset + 0x10000 > 1 << 32 or reset < RAM + RAM_SIZE and reset + 0x10000 > RAM:
        raise ValueError("Code and signature memory overlap or exceed RV32")
    lines = NOTICE.splitlines() + [".option norvc", ".option norelax",
             '.section .text.start,"ax",@progbits', ".globl _start, checked_start, checked_end, software_done",
             "_start:"]
    lines += [f"    addi x{index}, x0, 0" for index in range(1, 32)]
    lines += ["    la s0, begin_signature", "    li s6, 0", "    la t0, trap_vector", "    csrw mtvec, t0",
              "    csrw mepc, zero", "    csrw mcause, zero", "    csrw mtval, zero",
              f"    li t0, {0 if parameters['protectedMode'] else 0x1800}", "    csrw mstatus, t0",
              "    csrr s1, misa", "    li t0, 5", "    csrw mcountinhibit, t0", "    li t0, 100",
              "    csrw mcycle, t0", "    csrw mcycleh, zero", "    csrw minstret, t0", "    csrw minstreth, zero",
              "checked_start:", "    li t6, 0x12345678", "    addi a6, t6, 7", "    sw a6, 0(s0)",
              "    li t0, -127", "    sb t0, 4(s0)", "    lb t1, 4(s0)", "    lbu t2, 4(s0)",
              "    sw t1, 8(s0)", "    sw t2, 12(s0)", "    li t0, 0x87ab", "    sh t0, 6(s0)",
              "    lh t1, 6(s0)", "    lhu t2, 6(s0)", "    sw t1, 16(s0)", "    sw t2, 20(s0)",
              "    add t3, t1, t2", "    xor t4, t3, t6", "    slli t5, t4, 3", "    sw t5, 24(s0)",
              "    beq t1, t2, unexpected", "    blt t1, t2, branch_taken", "unexpected:",
              "    .word 0x0000007b", "branch_taken:"]
    if parameters["enableM"]:
        offset = 128
        for left, right in [(-43, 7), (0x80000000, -1), (-43, 0), (0, 0), (0x7fffffff, -7)]:
            lines += [f"    li t0, {left}", f"    li t1, {right}"]
            for operation in ("mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"):
                symbol = f"m_case_{offset}_{operation}"
                lines += [f".globl {symbol}", f"{symbol}:", f"    {operation} t2, t0, t1", f"    sw t2, {offset}(s0)"]
                offset += 4
    else:
        lines += ["    .word 0x02000033"]
    if parameters["enableC"]:
        lines += [f"    li sp, {RAM + 0x8000}", ".option rvc", "    c.nop", "    c.li a0, 3",
                  "    c.addi a0, 1", "    c.lui a1, 1", "    c.addi16sp sp, 16", "    c.addi4spn a2, sp, 4",
                  "    c.swsp a0, 0(sp)", "    c.lwsp a3, 0(sp)", "    c.sw a3, 0(a2)", "    c.lw a4, 0(a2)",
                  "    c.slli a0, 2", "    c.srli a0, 1", "    c.srai a0, 1", "    c.andi a0, -1",
                  "    c.mv a5, a0", "    c.add a5, a0", "    c.sub a5, a0", "    c.xor a5, a0",
                  "    c.or a5, a0", "    c.and a5, a0", "    c.j c_skip", "    .word 0x0000007b", "c_skip:",
                  "    c.li a0, 0", "    c.beqz a0, c_taken", "    .word 0x0000007b", "c_taken:",
                  "    c.li a0, 1", "    c.bnez a0, c_taken_again", "    .word 0x0000007b", "c_taken_again:",
                  "    c.jal c_subroutine", "    c.j c_after_call", "c_subroutine:", "    c.li a0, 9", "    c.jr ra",
                  "c_after_call:", "    la a5, c_indirect", "    c.jalr a5", "    c.j c_after_indirect",
                  "c_indirect:", "    c.addi a0, 1", "    c.jr ra", "c_after_indirect:", "    c.ebreak",
                  "    .hword 0x0005", "    .hword 0x0501", "    .hword 0x4001", "    .hword 0x6005",
                  "    .hword 0x0006", "    .hword 0x0502", "    .hword 0x8001", "    .hword 0x8401",
                  "    .hword 0x8006", "    .hword 0x9006", "    .hword 0x0000", "    .hword 0x8002",
                  "    .hword 0x4002", "    .hword 0x6101", "    .hword 0x1002", "    .hword 0x9c01",
                  "    .hword 0x8000", ".option norvc", "    sw a0, 320(s0)", "    sw a1, 324(s0)",
                  "    sw a3, 328(s0)", "    sw a4, 332(s0)", "    sw a5, 336(s0)"]
    offset = 768
    for vector, operand in enumerate((0x55aa00ff, 0x80000080, 0)):
        lines += [f"    li t6, {operand}", "    li a6, 0x1234567f"]
        for name, group, encoding in bit_encodings():
            symbol = f"b_case_{vector}_{name}"
            lines += [f".globl {symbol}", f"{symbol}:", f"    .word 0x{encoding:08x}", f"    sw a0, {offset}(s0)"]
            offset += 4
    lines += ["    csrr t0, mcycle", "    csrr t1, minstret", "    sw t0, 72(s0)", "    sw t1, 76(s0)",
              "    li s2, 1", "    li s3, 5", "    csrw mcountinhibit, s2",
              "    addi a0, x0, 7", "    addi a0, a0, 1", "    la a4, counter_word",
              "    sw a0, 0(a4)", "    lw a5, 0(a4)", "    beq a0, a5, counter_branch",
              "    .word 0x0000007b", "counter_branch:", "    .word 0x0000007b", "    csrr a1, minstret",
              "    csrw mcountinhibit, s3", "    csrr a2, minstret", "    csrr a3, minstreth",
              "    sw a1, 88(s0)", "    sw a2, 92(s0)",
              "    li t0, 0x90000000", "    jalr ra, t0, 0",
              "    fence", "    fence.i", "    li t6, -1"]
    for address in (0x30a, 0x31a):
        lines += [f"    csrrw a0, {address}, t6", f"    csrrs a0, {address}, zero",
                  f"    csrrc a0, {address}, t6", f"    csrrwi a0, {address}, 31",
                  f"    csrrsi a0, {address}, 0", f"    csrrci a0, {address}, 31"]
    if parameters["protectedMode"]:
        for index in range(16):
            lines += [f"    li t0, {(RAM + 0x4000 + index * 4) >> 2}", f"    csrw pmpaddr{index}, t0",
                      f"    csrr t1, pmpaddr{index}", f"    sw t1, {512 + index * 4}(s0)"]
        for index in range(4):
            lines += [f"    csrr t0, pmpcfg{index}", f"    sw t0, {576 + index * 4}(s0)"]
        lines += [f"    li a4, {RAM + 0x4000 + 15 * 4}", "    li t0, 0x91000000", "    csrw pmpcfg3, t0",
                  "    li a0, 0x12345678", "    sw a0, 0(a4)", "    lw a0, 0(a4)", "    sw a0, 600(s0)",
                  "    csrw pmpaddr15, zero", "    csrw pmpcfg3, zero", "    csrr t0, pmpaddr15",
                  "    csrr t1, pmpcfg3", "    sw t0, 604(s0)", "    sw t1, 608(s0)",
                  f"    li t0, {(RAM + 0x4200) >> 2}", "    csrw pmpaddr12, t0",
                  f"    li t0, {(RAM + 0x4300) >> 2}", "    csrw pmpaddr13, t0",
                  "    li t0, 0x91008900", "    csrw pmpcfg3, t0", "    csrw pmpaddr12, zero",
                  "    csrw pmpaddr13, zero", "    csrr t0, pmpaddr12", "    csrr t1, pmpaddr13",
                  "    sw t0, 612(s0)", "    sw t1, 616(s0)", f"    li a4, {RAM + 0x4200}",
                  "    sw a0, 0(a4)", "    lw a0, 0(a4)", "    sw a0, 620(s0)",
                  f"    li t0, {(RAM + 0x5000) >> 2}", "    csrw pmpaddr0, t0",
                  f"    li t0, {(RAM >> 2) | ((RAM_SIZE >> 3) - 1)}", "    csrw pmpaddr1, t0",
                  f"    li t0, {(reset >> 2) | ((0x10000 >> 3) - 1)}", "    csrw pmpaddr2, t0",
                  "    li t0, 0x001d1b10", "    csrw pmpcfg0, t0",
                  "    la t0, user_start", "    csrw mepc, t0", "    csrw mstatus, zero", "    mret",
                  "user_start:", "    csrr a0, 0x30a", "    csrr a0, 0x31a", f"    li a4, {RAM + 0x5000}",
                  "    lbu a0, -1(a4)", "    sw a0, 624(s0)", "    lbu a0, 0(a4)", "    lhu a0, 0(a4)",
                  "    lw a0, 0(a4)", "    sw a0, 0(a4)", "    lhu a0, 3(a4)", "    lw a0, 4(a4)",
                  "    sw a0, 628(s0)", "    ecall"]
    else:
        lines += ["    j checked_end"]
    lines += [".balign 4", "trap_vector:", "    csrr t0, mcause", "    csrr t1, mtval", "    slli t2, s6, 3",
              "    add t2, s0, t2", f"    li t3, {TRAP_OFFSET}", "    add t2, t2, t3",
              "    sw t0, 0(t2)", "    sw t1, 4(t2)", "    addi s6, s6, 1",
              "    li t1, 1", "    beq t0, t1, fetch_return",
              "    li t1, 8", "    beq t0, t1, checked_end", "    csrr t0, mepc", "    lhu t1, 0(t0)",
              "    andi t1, t1, 3", "    li t2, 3", "    beq t1, t2, long_fault", "    addi t0, t0, 2",
              "    j resume_fault", "long_fault:", "    addi t0, t0, 4", "resume_fault:",
              "    csrw mepc, t0", "    mret", "fetch_return:", "    csrw mepc, ra", "    mret",
              "checked_end:", "    addi x0, x0, 0", "    la t0, tohost",
              "    li t1, 1", "    sw t1, 0(t0)", "    sw zero, 4(t0)", "software_done:", "    j software_done",
              '.section .data,"aw",@progbits', ".balign 16",
              ".globl begin_signature, end_signature, tohost, fromhost", "begin_signature:",
              f"    .fill {SIGNATURE_WORDS},4,0", "end_signature:", ".balign 8", "tohost: .dword 0", "fromhost: .dword 0",
              ".balign 4", "counter_word: .word 0"]
    return "\n".join(lines) + "\n"


def linker(parameters):
    reset = parameters["resetVector"]
    sections = [(reset, ".text", "*(.text.start) *(.text*)", "text", 5),
                (RAM, ".data", "*(.data*) *(.bss*)", "data", 6)]
    sections.sort()
    segments = " ".join(f"{name} PT_LOAD FLAGS({flags});" for _, _, _, name, flags in sections)
    body = "\n".join(f" . = {address}; {section} : {{ {contents} }} :{name}"
                     for address, section, contents, name, _ in sections)
    return (NOTICE + "OUTPUT_ARCH(riscv)\nENTRY(_start)\n"
            f"PHDRS {{ {segments} }}\nSECTIONS {{\n{body}\n"
            " /DISCARD/ : { *(.riscv.attributes) *(.comment) }\n}\n")
