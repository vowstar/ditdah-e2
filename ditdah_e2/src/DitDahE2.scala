// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

private class PipelineReset extends Bundle:
  val value = Aligned(Reset())

@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, CoreIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2"
  def architecture(p: Parameters) =
    val io = summon[Interface[CoreIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    val systemReset = Wire(Bool())
    systemReset := false.B
    val resets = Wire(new PipelineReset)
    val coreReset = resets.value
    coreReset := (io.reset.asBool | systemReset).asReset
    given ResetScope = ResetScope.syncActiveHigh(coreReset)
    val debugStop = Wire(Bool())
    val debugResume = Wire(Bool())
    val debugResumePc = Wire(UInt(32))
    val debugResumeUser = Wire(Bool())
    val debugStep = Wire(Bool())
    val debugFreeze = Wire(Bool())
    val debugAccess = Wire(Bool())
    val debugBreakMachine = Wire(Bool())
    val debugBreakUser = Wire(Bool())
    debugStop := false.B
    debugResume := false.B
    debugResumePc := 0.U(32)
    debugResumeUser := false.B
    debugStep := false.B
    debugFreeze := false.B
    debugAccess := false.B
    debugBreakMachine := false.B
    debugBreakUser := false.B
    val programData = Wire(new MemoryPort)
    io.data :<>= programData
    val fetch = Fetch.instantiate(p)
    fetch.io.clock := io.clock
    fetch.io.reset := coreReset
    val csr = Csr.instantiate(p)
    csr.io.clock := io.clock
    csr.io.reset := coreReset
    csr.io.interrupts :<= io.interrupts
    csr.io.timeValue := io.timeValue
    csr.io.debugAccess := debugAccess
    csr.io.debugHalted := debugFreeze
    csr.io.debugRestore := debugResume
    csr.io.debugUser := debugResumeUser
    fetch.io.machine := !csr.io.userMode
    csr.io.instructionProtection.address := fetch.io.memory.request.bits.address
    csr.io.instructionProtection.size := 2.U(2)
    csr.io.instructionProtection.machine := fetch.io.memory.request.bits.machine
    csr.io.instructionProtection.kind := 2.U(2)
    if p.protectedMode then
      val protection = MemoryProtection.instantiate(p)
      protection.io.clock := io.clock
      protection.io.reset := coreReset
      protection.io.allowed := csr.io.instructionProtection.allowed
      protection.io.input :<>= fetch.io.memory
      io.instruction :<>= protection.io.output
    else io.instruction :<>= fetch.io.memory
    val xValid = RegInit(false.B)
    val x = Reg(new Instruction)
    val xUser = RegInit(false.B)
    val mValid = RegInit(false.B)
    val m = Reg(new Completion)
    val sent = RegInit(false.B)
    val architecturalPc = RegInit(BigInt(p.resetVector).U(32))
    val sleeping = RegInit(false.B)
    val registers = Seq.fill(31)(RegInit(0.U(32)))

    val localWake = csr.io.interruptPending =/= 0.U(12)
    val eligibleInterrupt = localWake & csr.io.interruptsEnabled & !debugStop & !debugStep
    val interrupt = !mValid & eligibleInterrupt
    val interruptCause = csr.io.interruptPending.asBits.bit(11).?(0x8000000bL.U(32),
      csr.io.interruptPending.asBits.bit(3).?(0x80000003L.U(32), 0x80000007L.U(32)))
    val waking = sleeping & localWake & !debugStop

    val memory = m.load | m.store
    csr.io.dataProtection.address := m.address
    csr.io.dataProtection.size := m.size
    csr.io.dataProtection.machine := csr.io.dataMachine
    csr.io.dataProtection.kind := m.store.?(1.U(2), 0.U(2))
    val denied = mValid & memory & !m.trap & !csr.io.dataProtection.allowed
    programData.request.valid := mValid & memory & !m.trap & !sent & !denied
    programData.request.bits.address := m.address
    programData.request.bits.machine := csr.io.dataMachine
    programData.request.bits.write := m.store
    val lane = m.address.asBits.bits(1, 0).asUInt
    val shift = (m.address.asBits.bits(1, 0) ## 0.B(3)).asUInt
    programData.request.bits.data := (m.storeData << shift).asBits.bits(31, 0).asUInt
    val mask = (m.size === 0.U(2)).?(1.U(4), (m.size === 1.U(2)).?(3.U(4), 15.U(4)))
    programData.request.bits.mask := m.store.?((mask << lane).asBits.bits(3, 0).asUInt, 0.U(4))
    programData.request.bits.size := m.size
    programData.response.ready := mValid & memory & sent
    val response = programData.response.valid & programData.response.ready
    val csrError = m.csr & csr.io.illegal
    val protectionUpdate = mValid & m.csr & m.csrWrite & csr.io.protectionSelected & !csrError & !m.trap
    val synchronize = m.fenceI | protectionUpdate
    val synchronizing = mValid & synchronize & !m.trap
    val complete = mValid & (m.trap | denied | (!memory & (!synchronize | fetch.io.idle)) | response)
    val failed = m.trap | csrError | denied | (response & programData.response.bits.fault)
    val trap = complete & failed
    val returning = complete & m.mret & !failed
    val waiting = complete & m.wfi & !failed
    val synchronized = complete & synchronize & !failed
    val debugBreakpoint = complete & m.debugBreak & !failed
    val finalCause = m.trap.?(m.cause, csrError.?(2.U(32), m.store.?(7.U(32), 5.U(32))))
    val finalTval = m.trap.?(m.tval, csrError.?(m.instruction.word, m.address))
    csr.io.address := m.csrAddress
    csr.io.operand := m.csrOperand
    csr.io.operation := m.csrOperation
    csr.io.writeRequested := m.csrWrite
    csr.io.commit := complete & m.csr & !failed
    csr.io.trap := trap | interrupt
    csr.io.trapPc := interrupt.?(architecturalPc, m.instruction.pc)
    csr.io.cause := interrupt.?(interruptCause, finalCause)
    csr.io.tval := interrupt.?(0.U(32), finalTval)
    csr.io.mret := returning
    csr.io.retire := complete & !failed & !debugBreakpoint
    io.interrupt.valid := interrupt
    io.interrupt.pc := architecturalPc
    io.interrupt.target := csr.io.trapTarget
    io.interrupt.cause := interruptCause
    io.sleeping := sleeping
    val loaded = (programData.response.bits.data >> shift).asBits
    val loadValue = Wire(UInt(32))
    loadValue := loaded.asUInt
    when(m.size === 0.U(2)) {
      loadValue := ((loaded.bit(7) & !m.unsignedLoad).?(0xffffff.B(24), 0.B(24)) ## loaded.bits(7, 0)).asUInt
    }
    when(m.size === 1.U(2)) {
      loadValue := ((loaded.bit(15) & !m.unsignedLoad).?(0xffff.B(16), 0.B(16)) ## loaded.bits(15, 0)).asUInt
    }
    val writeback = m.csr.?(csr.io.readData, m.load.?(loadValue, m.value))
    io.retire.valid := complete & !debugBreakpoint
    io.retire.userMode := m.userMode
    io.retire.pc := m.instruction.pc
    io.retire.word := m.instruction.word
    io.retire.nextPc := failed.?(csr.io.trapTarget, m.mret.?(csr.io.returnPc, m.nextPc))
    io.retire.rd := m.rd
    io.retire.writes := complete & !failed & m.writes & (m.rd =/= 0.U(5))
    io.retire.value := io.retire.writes.?(writeback, 0.U(32))
    io.retire.trap := trap
    io.retire.cause := finalCause
    io.retire.tval := finalTval
    when(complete & !debugBreakpoint) { architecturalPc := io.retire.nextPc }
    when(debugResume) { architecturalPc := debugResumePc }
    when(interrupt) { architecturalPc := csr.io.trapTarget }
    for i <- 1 to 31 do
      when(io.retire.writes & (m.rd === i.U(5))) { registers(i - 1) := writeback }

    val decoded = Wire(UInt(32))
    val encodingLegal = Wire(Bool())
    decoded := x.word
    encodingLegal := true.B
    if p.enableC then
      val compressed = Compressed.instantiate(p)
      compressed.io.raw := x.word.asBits.bits(15, 0).asUInt
      val short = x.length === 2.U(3)
      decoded := short.?(compressed.io.instruction, x.word)
      encodingLegal := short.?(compressed.io.legal, x.word.asBits.bits(4, 0) =/= 31.B(5))
    val bits = decoded.asBits
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
    val isMultiplyDivide = if p.enableM then (opcode === 0x33.B(7)) & (funct7 === 1.B(7)) else false.B
    val isLui = opcode === 0x37.B(7)
    val isAuipc = opcode === 0x17.B(7)
    val isLoad = (opcode === 0x03.B(7)) & ((funct3.asUInt <= 2.U(3)) |
      (funct3 === 4.B(3)) | (funct3 === 5.B(3)))
    val isStore = (opcode === 0x23.B(7)) & (funct3.asUInt <= 2.U(3))
    val isBranch = (opcode === 0x63.B(7)) & (funct3.bits(2, 1) =/= 1.B(2))
    val isJal = opcode === 0x6f.B(7)
    val isJalr = (opcode === 0x67.B(7)) & (funct3 === 0.B(3))
    val isBreak = decoded === 0x00100073.U(32)
    val isDebugBreak = isBreak & xUser.?(debugBreakUser, debugBreakMachine)
    val isCall = decoded === 0x00000073.U(32)
    val isFence = (opcode === 0x0f.B(7)) & (funct3 === 0.B(3))
    val isFenceI = (opcode === 0x0f.B(7)) & (funct3 === 1.B(3))
    val isCsr = (opcode === 0x73.B(7)) & (funct3.bits(1, 0) =/= 0.B(2))
    val isMret = decoded === 0x30200073.U(32)
    val isWfi = decoded === 0x10500073.U(32)
    val legal = encodingLegal & (isImmediate | isRegister | isMultiplyDivide | isLui | isAuipc | isLoad | isStore | isBranch | isJal | isJalr | isBreak | isCall | isFence | isFenceI | isCsr | isMret | isWfi)
    val use1 = isImmediate | isRegister | isMultiplyDivide | isLoad | isStore | isBranch | isJalr | (isCsr & !funct3.bit(2))
    val use2 = isRegister | isMultiplyDivide | isStore | isBranch
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
    val serialM = mValid & (m.csr | m.mret | m.wfi | m.fenceI)
    val arithmeticReady = Wire(Bool())
    val arithmeticValue = Wire(UInt(32))
    arithmeticReady := true.B
    arithmeticValue := 0.U(32)
    val advance = xValid & (!mValid | complete) & !loadUse & !trap & !serialM &
      (!(isCsr | isMret | isWfi | isFenceI) | !mValid) & !eligibleInterrupt & !sleeping &
      (!isMultiplyDivide | x.fault | arithmeticReady) & !debugStop
    io.mulDiv.start := false.B
    io.mulDiv.resultValid := false.B
    io.mulDiv.finish := false.B
    io.mulDiv.cancel := false.B
    io.mulDiv.pc := 0.U(32)
    io.mulDiv.value := 0.U(32)
    if p.enableM then
      val multiplyDivide = MultiplyDivide.instantiate(p)
      val arithmeticPending = RegInit(false.B)
      multiplyDivide.io.clock := io.clock
      multiplyDivide.io.reset := coreReset
      multiplyDivide.io.cancel := trap | interrupt | debugStop
      multiplyDivide.io.request.valid := xValid & isMultiplyDivide & !arithmeticPending &
        !loadUse & !serialM & !trap & !eligibleInterrupt & !sleeping & !x.fault & !debugStop
      multiplyDivide.io.request.bits.operation := funct3.asUInt
      multiplyDivide.io.request.bits.left := a
      multiplyDivide.io.request.bits.right := b
      multiplyDivide.io.response.ready := advance & isMultiplyDivide
      val started = multiplyDivide.io.request.valid & multiplyDivide.io.request.ready
      val finished = multiplyDivide.io.response.valid & multiplyDivide.io.response.ready
      arithmeticReady := arithmeticPending & multiplyDivide.io.response.valid
      arithmeticValue := multiplyDivide.io.response.bits
      io.mulDiv.start := started
      io.mulDiv.resultValid := arithmeticPending & multiplyDivide.io.response.valid
      io.mulDiv.finish := finished
      io.mulDiv.cancel := arithmeticPending & (trap | interrupt | debugStop)
      io.mulDiv.pc := x.pc
      io.mulDiv.value := multiplyDivide.io.response.valid.?(multiplyDivide.io.response.bits, 0.U(32))
      when(started) { arithmeticPending := true.B }
      when(finished | trap | interrupt | debugStop) { arithmeticPending := false.B }
    io.loadUse := xValid & loadUse
    io.forward := advance & !m.load & (match1 | match2)
    io.memoryWait := mValid & memory & !complete

    val sign = bits.bit(31)
    val immI = (sign.?(0xfffff.B(20), 0.B(20)) ## bits.bits(31, 20)).asUInt
    val immS = (sign.?(0xfffff.B(20), 0.B(20)) ## bits.bits(31, 25) ## bits.bits(11, 7)).asUInt
    val immB = (sign.?(0x7ffff.B(19), 0.B(19)) ## bits.bits(31, 31) ## bits.bits(7, 7) ## bits.bits(30, 25) ## bits.bits(11, 8) ## 0.B(1)).asUInt
    val immJ = (sign.?(0x7ff.B(11), 0.B(11)) ## bits.bits(31, 31) ## bits.bits(19, 12) ## bits.bits(20, 20) ## bits.bits(30, 21) ## 0.B(1)).asUInt
    val sequential = (x.pc + x.length).asBits.bits(31, 0).asUInt
    val address = (a + isStore.?(immS, immI)).asBits.bits(31, 0).asUInt
    val compare = Wire(Bool())
    compare := a === b
    when(funct3.bits(2, 1) === 2.B(2)) { compare := a.asBits.asSInt < b.asBits.asSInt }
    when(funct3.bits(2, 1) === 3.B(2)) { compare := a < b }
    val branchTaken = compare ^ funct3.bit(0)
    val jump = isJal | isJalr | (isBranch & branchTaken)
    val relative = (x.pc + isJal.?(immJ, immB)).asBits.bits(31, 0).asUInt
    val target = isJalr.?((address.asBits.bits(31, 1) ## 0.B(1)).asUInt, relative)
    val badTarget = jump & (if p.enableC then target.asBits.bit(0) else target.asBits.bits(1, 0) =/= 0.B(2))
    val size = funct3.bits(1, 0).asUInt
    val badData = (isLoad | isStore) & (
      ((size === 2.U(2)) & (address.asBits.bits(1, 0) =/= 0.B(2))) |
      ((size === 1.U(2)) & address.asBits.bit(0)))
    val systemFault = (isMret & xUser) | (isWfi & csr.io.wfiIllegal)
    val fault = x.fault | !legal | (isBreak & !isDebugBreak) | isCall | badTarget | badData | systemFault
    val cause = Wire(UInt(32))
    val tval = Wire(UInt(32))
    cause := 2.U(32)
    tval := x.word
    when(isBreak) { cause := 3.U(4); tval := x.pc }
    when(isCall) { cause := xUser.?(8.U(32), 11.U(32)); tval := 0.U(32) }
    when(badData) { cause := isStore.?(6.U(32), 4.U(32)); tval := address }
    when(badTarget) { cause := 0.U(32); tval := target }
    when(x.fault) { cause := 1.U(32); tval := x.faultAddress }
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
    when(isMultiplyDivide) { value := arithmeticValue }

    val branchRedirect = advance & jump & !fault
    val redirect = trap | interrupt | returning | waiting | waking | synchronized | branchRedirect | debugResume
    fetch.io.redirect := redirect
    fetch.io.target := debugResume.?(debugResumePc, (trap | interrupt).?(csr.io.trapTarget,
      returning.?(csr.io.returnPc, (waiting | synchronized).?(m.nextPc, waking.?(architecturalPc, target)))))
    fetch.io.pause := trap | interrupt | sleeping | waiting | synchronizing | (advance & isFenceI & !fault) | debugStop
    fetch.io.output.ready := (!xValid | advance) & !redirect & !sleeping & !eligibleInterrupt & !debugStop
    io.redirect := redirect
    when(complete) { mValid := false.B }
    when(programData.request.valid & programData.request.ready) { sent := true.B }
    when(advance) {
      xValid := false.B
      mValid := true.B
      sent := false.B
      m.instruction :<= x
      m.userMode := xUser
      m.debugBreak := isDebugBreak
      m.nextPc := jump.?(target, sequential)
      m.rd := bits.bits(11, 7).asUInt
      m.writes := isImmediate | isRegister | isMultiplyDivide | isLui | isAuipc | isLoad | isJal | isJalr | isCsr
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
      m.wfi := isWfi
      m.fenceI := isFenceI
      m.trap := fault
      m.cause := cause
      m.tval := tval
    }
    when(fetch.io.output.valid & fetch.io.output.ready) {
      xValid := true.B
      x :<= fetch.io.output.bits
      xUser := csr.io.userMode
    }
    when(waiting) { sleeping := !localWake & !debugStep }
    when(waking | trap | interrupt | debugStop | debugResume) { sleeping := false.B }
    when(trap | interrupt | returning | waiting | waking | synchronized) { xValid := false.B; mValid := false.B }
    when(debugStop | debugResume) { xValid := false.B }
    if p.enableDebug then
      val dm = DebugModule.instantiate(p)
      val debug = DebugHart.instantiate(DebugHartParameters(p.resetVector, p.enableC, p.protectedMode))
      dm.io.clock := io.clock
      dm.io.reset := io.reset
      dm.io.dmi :<>= io.dmi.get
      debug.io.clock := io.clock
      debug.io.reset := io.reset
      debug.io.debug :<>= dm.io.hart
      debug.io.core.empty := !mValid
      debug.io.core.fetchIdle := fetch.io.idle
      debug.io.core.architecturalPc := architecturalPc
      debug.io.core.userMode := csr.io.userMode
      debug.io.core.completed := complete & !debugBreakpoint
      debug.io.core.breakpoint := debugBreakpoint
      debug.io.core.breakpointPc := m.instruction.pc
      debugStop := debug.io.core.stop
      debugResume := debug.io.core.resume
      debugResumePc := debug.io.core.resumePc
      debugResumeUser := debug.io.core.resumeUser
      debugStep := debug.io.core.singleStep
      debugFreeze := debug.io.core.freezeCounters
      debugAccess := debug.io.debug.status.halted
      debugBreakMachine := debug.io.core.ebreakMachine
      debugBreakUser := debug.io.core.ebreakUser
      systemReset := debug.io.core.coreReset
      io.systemReset.get := systemReset
      val register = debug.io.backend.register
      val gpr = (register >= 0x1000.U(16)) & (register <= 0x101f.U(16))
      val csrRegister = register <= 0x0fff.U(16)
      debug.io.backend.readData := csrRegister.?(csr.io.readData, 0.U(32))
      debug.io.backend.error := !(gpr | csrRegister) | (csrRegister & csr.io.illegal)
      for index <- 1 to 31 do
        when(register === (0x1000 + index).U(16)) {
          debug.io.backend.readData := registers(index - 1)
          when(debug.io.backend.writePulse) { registers(index - 1) := debug.io.backend.writeData }
        }
      when(debugAccess) {
        csr.io.address := register.asBits.bits(11, 0).asUInt
        csr.io.operand := debug.io.backend.writeData
        csr.io.operation := 1.U(2)
        csr.io.writeRequested := debug.io.backend.writeRequested
        csr.io.commit := debug.io.backend.writePulse & csrRegister
        csr.io.dataProtection.address := debug.io.protection.address
        csr.io.dataProtection.size := debug.io.protection.size
        csr.io.dataProtection.kind := debug.io.protection.write.?(1.U(2), 0.U(2))
      }
      debug.io.protection.allowed := csr.io.dataProtection.allowed
      debug.io.protection.machine := csr.io.dataMachine
      val debugMemory = debugAccess | debug.io.memory.request.valid | debug.io.memory.response.ready
      debug.io.memory.request.ready := io.data.request.ready & debugMemory
      debug.io.memory.response.valid := io.data.response.valid & debugMemory
      debug.io.memory.response.bits :<= io.data.response.bits
      when(debugMemory) {
        io.data.request.valid := debug.io.memory.request.valid
        io.data.request.bits :<= debug.io.memory.request.bits
        io.data.response.ready := debug.io.memory.response.ready
        programData.request.ready := false.B
        programData.response.valid := false.B
      }
