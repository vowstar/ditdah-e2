// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, CoreIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2"
  def architecture(p: Parameters) =
    val io = summon[Interface[CoreIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val fetch = Fetch.instantiate(p)
    fetch.io.clock := io.clock
    fetch.io.reset := io.reset
    io.instruction :<>= fetch.io.memory
    val csr = Csr.instantiate(p)
    csr.io.clock := io.clock
    csr.io.reset := io.reset
    val xValid = RegInit(false.B)
    val x = Reg(new Instruction)
    val mValid = RegInit(false.B)
    val m = Reg(new Completion)
    val sent = RegInit(false.B)
    val registers = Seq.fill(31)(RegInit(0.U(32)))

    val memory = m.load | m.store
    io.data.request.valid := mValid & memory & !m.trap & !sent
    io.data.request.bits.address := m.address
    io.data.request.bits.write := m.store
    val lane = m.address.asBits.bits(1, 0).asUInt
    val shift = (m.address.asBits.bits(1, 0) ## 0.B(3)).asUInt
    io.data.request.bits.data := (m.storeData << shift).asBits.bits(31, 0).asUInt
    val mask = (m.size === 0.U(2)).?(1.U(4), (m.size === 1.U(2)).?(3.U(4), 15.U(4)))
    io.data.request.bits.mask := m.store.?((mask << lane).asBits.bits(3, 0).asUInt, 0.U(4))
    io.data.request.bits.size := m.size
    io.data.response.ready := mValid & memory & sent
    val response = io.data.response.valid & io.data.response.ready
    val complete = mValid & (m.trap | !memory | response)
    val csrError = m.csr & csr.io.illegal
    val failed = m.trap | csrError | (response & io.data.response.bits.fault)
    val trap = complete & failed
    val returning = complete & m.mret & !failed
    val finalCause = m.trap.?(m.cause, csrError.?(2.U(32), m.store.?(7.U(32), 5.U(32))))
    val finalTval = m.trap.?(m.tval, csrError.?(m.instruction.word, m.address))
    csr.io.address := m.csrAddress
    csr.io.operand := m.csrOperand
    csr.io.operation := m.csrOperation
    csr.io.writeRequested := m.csrWrite
    csr.io.commit := complete & m.csr & !failed
    csr.io.trap := trap
    csr.io.trapPc := m.instruction.pc
    csr.io.cause := finalCause
    csr.io.tval := finalTval
    csr.io.mret := returning
    val loaded = (io.data.response.bits.data >> shift).asBits
    val loadValue = Wire(UInt(32))
    loadValue := loaded.asUInt
    when(m.size === 0.U(2)) {
      loadValue := ((loaded.bit(7) & !m.unsignedLoad).?(0xffffff.B(24), 0.B(24)) ## loaded.bits(7, 0)).asUInt
    }
    when(m.size === 1.U(2)) {
      loadValue := ((loaded.bit(15) & !m.unsignedLoad).?(0xffff.B(16), 0.B(16)) ## loaded.bits(15, 0)).asUInt
    }
    val writeback = m.csr.?(csr.io.readData, m.load.?(loadValue, m.value))
    io.retire.valid := complete
    io.retire.pc := m.instruction.pc
    io.retire.word := m.instruction.word
    io.retire.nextPc := failed.?(csr.io.trapTarget, m.mret.?(csr.io.returnPc, m.nextPc))
    io.retire.rd := m.rd
    io.retire.writes := complete & !failed & m.writes & (m.rd =/= 0.U(5))
    io.retire.value := io.retire.writes.?(writeback, 0.U(32))
    io.retire.trap := trap
    io.retire.cause := finalCause
    io.retire.tval := finalTval
    for i <- 1 to 31 do
      when(io.retire.writes & (m.rd === i.U(5))) { registers(i - 1) := writeback }

    val bits = x.word.asBits
    val opcode = bits.bits(6, 0)
    val rs1 = bits.bits(19, 15).asUInt
    val rs2 = bits.bits(24, 20).asUInt
    val funct3 = bits.bits(14, 12)
    val funct7 = bits.bits(31, 25)
    val isImmediate = (opcode === 0x13.B(7)) & (
      ((funct3 =/= 1.B(3)) & (funct3 =/= 5.B(3))) |
      (funct7 === 0.B(7)) | ((funct3 === 5.B(3)) & (funct7 === 32.B(7))))
    val isRegister = (opcode === 0x33.B(7)) & ((funct7 === 0.B(7)) |
      ((funct7 === 32.B(7)) & ((funct3 === 0.B(3)) | (funct3 === 5.B(3)))))
    val isLui = opcode === 0x37.B(7)
    val isAuipc = opcode === 0x17.B(7)
    val isLoad = (opcode === 0x03.B(7)) & ((funct3.asUInt <= 2.U(3)) |
      (funct3 === 4.B(3)) | (funct3 === 5.B(3)))
    val isStore = (opcode === 0x23.B(7)) & (funct3.asUInt <= 2.U(3))
    val isBranch = (opcode === 0x63.B(7)) & (funct3.bits(2, 1) =/= 1.B(2))
    val isJal = opcode === 0x6f.B(7)
    val isJalr = (opcode === 0x67.B(7)) & (funct3 === 0.B(3))
    val isBreak = x.word === 0x00100073.U(32)
    val isCall = x.word === 0x00000073.U(32)
    val isFence = (opcode === 0x0f.B(7)) & (funct3 === 0.B(3))
    val isCsr = (opcode === 0x73.B(7)) & (funct3.bits(1, 0) =/= 0.B(2))
    val isMret = x.word === 0x30200073.U(32)
    val legal = isImmediate | isRegister | isLui | isAuipc | isLoad | isStore | isBranch | isJal | isJalr | isBreak | isCall | isFence | isCsr | isMret
    val use1 = isImmediate | isRegister | isLoad | isStore | isBranch | isJalr | (isCsr & !funct3.bit(2))
    val use2 = isRegister | isStore | isBranch
    val a = Wire(UInt(32))
    val b = Wire(UInt(32))
    a := 0.U(32)
    b := 0.U(32)
    for i <- 1 to 31 do
      when(rs1 === i.U(5)) { a := registers(i - 1) }
      when(rs2 === i.U(5)) { b := registers(i - 1) }
    val producer = mValid & m.writes & (m.rd =/= 0.U(5)) & !m.trap
    val match1 = producer & use1 & (rs1 === m.rd)
    val match2 = producer & use2 & (rs2 === m.rd)
    when(match1 & !m.load) { a := m.value }
    when(match2 & !m.load) { b := m.value }
    val loadUse = m.load & (match1 | match2)
    val serialM = mValid & (m.csr | m.mret)
    val advance = xValid & (!mValid | complete) & !loadUse & !trap & !serialM & (!(isCsr | isMret) | !mValid)
    io.loadUse := xValid & loadUse
    io.forward := advance & !m.load & (match1 | match2)
    io.memoryWait := mValid & memory & !complete

    val sign = bits.bit(31)
    val immI = (sign.?(0xfffff.B(20), 0.B(20)) ## bits.bits(31, 20)).asUInt
    val immS = (sign.?(0xfffff.B(20), 0.B(20)) ## bits.bits(31, 25) ## bits.bits(11, 7)).asUInt
    val immB = (sign.?(0x7ffff.B(19), 0.B(19)) ## bits.bits(31, 31) ## bits.bits(7, 7) ## bits.bits(30, 25) ## bits.bits(11, 8) ## 0.B(1)).asUInt
    val immJ = (sign.?(0x7ff.B(11), 0.B(11)) ## bits.bits(31, 31) ## bits.bits(19, 12) ## bits.bits(20, 20) ## bits.bits(30, 21) ## 0.B(1)).asUInt
    val sequential = (x.pc + 4.U(32)).asBits.bits(31, 0).asUInt
    val address = (a + isStore.?(immS, immI)).asBits.bits(31, 0).asUInt
    val compare = Wire(Bool())
    compare := a === b
    when(funct3.bits(2, 1) === 2.B(2)) { compare := a.asBits.asSInt < b.asBits.asSInt }
    when(funct3.bits(2, 1) === 3.B(2)) { compare := a < b }
    val branchTaken = compare ^ funct3.bit(0)
    val jump = isJal | isJalr | (isBranch & branchTaken)
    val relative = (x.pc + isJal.?(immJ, immB)).asBits.bits(31, 0).asUInt
    val target = isJalr.?((address.asBits.bits(31, 1) ## 0.B(1)).asUInt, relative)
    val badTarget = jump & (target.asBits.bits(1, 0) =/= 0.B(2))
    val size = funct3.bits(1, 0).asUInt
    val badData = (isLoad | isStore) & (
      ((size === 2.U(2)) & (address.asBits.bits(1, 0) =/= 0.B(2))) |
      ((size === 1.U(2)) & address.asBits.bit(0)))
    val fault = x.fault | !legal | isBreak | isCall | badTarget | badData
    val cause = Wire(UInt(32))
    val tval = Wire(UInt(32))
    cause := 2.U(32)
    tval := x.word
    when(isBreak) { cause := 3.U(4); tval := x.pc }
    when(isCall) { cause := 11.U(4); tval := 0.U(32) }
    when(badData) { cause := isStore.?(6.U(32), 4.U(32)); tval := address }
    when(badTarget) { cause := 0.U(32); tval := target }
    when(x.fault) { cause := 1.U(32); tval := x.pc }
    val value = Wire(UInt(32))
    val rhs = isRegister.?(b, immI)
    val amount = rhs.asBits.bits(4, 0).asUInt
    value := (a + rhs).asBits.bits(31, 0).asUInt
    when(isRegister & bits.bit(30) & (funct3 === 0.B(3))) { value := (a - rhs).asBits.bits(31, 0).asUInt }
    when(funct3 === 1.B(3)) { value := (a << amount).asBits.bits(31, 0).asUInt }
    when(funct3 === 2.B(3)) { value := (a.asBits.asSInt < rhs.asBits.asSInt).asBits.asUInt }
    when(funct3 === 3.B(3)) { value := (a < rhs).asBits.asUInt }
    when(funct3 === 4.B(3)) { value := (a.asBits ^ rhs.asBits).asUInt }
    when(funct3 === 5.B(3)) { value := bits.bit(30).?((a.asBits.asSInt >> amount).asBits.asUInt, a >> amount) }
    when(funct3 === 6.B(3)) { value := (a.asBits | rhs.asBits).asUInt }
    when(funct3 === 7.B(3)) { value := (a.asBits & rhs.asBits).asUInt }
    when(isLui) { value := (bits.bits(31, 12) ## 0.B(12)).asUInt }
    when(isAuipc) { value := (x.pc + (bits.bits(31, 12) ## 0.B(12)).asUInt).asBits.bits(31, 0).asUInt }
    when(isJal | isJalr) { value := sequential }

    val branchRedirect = advance & jump & !fault
    val redirect = trap | returning | branchRedirect
    fetch.io.redirect := redirect
    fetch.io.target := trap.?(csr.io.trapTarget, returning.?(csr.io.returnPc, target))
    fetch.io.pause := trap
    fetch.io.output.ready := (!xValid | advance) & !redirect
    io.redirect := redirect
    when(complete) { mValid := false.B }
    when(io.data.request.valid & io.data.request.ready) { sent := true.B }
    when(advance) {
      xValid := false.B
      mValid := true.B
      sent := false.B
      m.instruction :<= x
      m.nextPc := jump.?(target, sequential)
      m.rd := bits.bits(11, 7).asUInt
      m.writes := isImmediate | isRegister | isLui | isAuipc | isLoad | isJal | isJalr | isCsr
      m.value := value
      m.load := isLoad
      m.store := isStore
      m.address := address
      m.storeData := b
      m.size := size
      m.unsignedLoad := funct3.bit(2)
      m.csr := isCsr
      m.csrAddress := bits.bits(31, 20).asUInt
      m.csrOperation := funct3.bits(1, 0).asUInt
      m.csrOperand := funct3.bit(2).?((0.B(27) ## bits.bits(19, 15)).asUInt, a)
      m.csrWrite := (funct3.bits(1, 0) === 1.B(2)) | (rs1 =/= 0.U(5))
      m.mret := isMret
      m.trap := fault
      m.cause := cause
      m.tval := tval
    }
    when(fetch.io.output.valid & fetch.io.output.ready) {
      xValid := true.B
      x :<= fetch.io.output.bits
    }
    when(trap | returning) { xValid := false.B; mValid := false.B }
