// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
import java.lang.foreign.Arena
import org.llvm.mlir.scalalib.capi.ir.{Block, Context}

private class PipelineReset extends Bundle:
  val value = Aligned(Reset())

@generator
object DitDahE2 extends Generator[Parameters, UnitLayers, CoreIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2"
  // Keep retirement observation below the JVM method-size limit.
  private def observeRetirement(body: () => Unit): Unit = body()
  private def triggerActions(p: Parameters, csr: Interface[CsrIO], x: Referable[Instruction],
      xValid: Referable[Bool], xInjected: Referable[Bool], xUser: Referable[Bool], debugAccess: Referable[Bool],
      mValid: Referable[Bool], eligibleInterrupt: Referable[Bool], sleeping: Referable[Bool],
      debugResume: Referable[Bool], trap: Referable[Bool], interrupt: Referable[Bool],
      returning: Referable[Bool])(using Arena, Context, Block, InstanceContext): (Wire[Bool], Wire[Bool], Wire[Bool]) =
    val matched = Wire(Bool())
    val native = Wire(Bool())
    val debug = Wire(Bool())
    matched := false.B
    native := false.B
    debug := false.B
    if p.triggerCount == 2 then
      csr.trigger.get.pc := x.pc
      csr.trigger.get.valid := xValid & !xInjected
      csr.trigger.get.user := xUser
      csr.trigger.get.debug := debugAccess
      csr.trigger.get.ready := !mValid & !eligibleInterrupt & !sleeping & !debugResume
      csr.trigger.get.trap := trap | interrupt
      csr.trigger.get.mret := returning
      matched := csr.trigger.get.matched
      native := csr.trigger.get.nativeAction
      debug := csr.trigger.get.debugAction
    (matched, native, debug)
  private def driveTrap(csr: Interface[CsrIO], io: Interface[CoreIO], m: Referable[Completion],
      complete: Referable[Bool], failed: Referable[Bool], trap: Referable[Bool],
      interrupt: Referable[Bool], returning: Referable[Bool], debugBreakpoint: Referable[Bool],
      architecturalPc: Referable[UInt], interruptCause: Referable[UInt], finalCause: Referable[UInt],
      finalTval: Referable[UInt], coreReset: Referable[Reset], sleeping: Referable[Bool])
      (using Arena, Context, Block, InstanceContext): Unit =
    csr.address := m.csrAddress
    csr.operand := m.csrOperand
    csr.operation := m.csrOperation
    csr.writeRequested := m.csrWrite
    val debugLocal = m.injected & m.csr & ((m.csrAddress === 0x7b0.U(12)) | (m.csrAddress === 0x7b1.U(12)))
    csr.commit := complete & m.csr & !failed & !debugLocal
    csr.trap := trap | interrupt
    csr.trapPc := interrupt.?(architecturalPc, m.instruction.pc)
    csr.cause := interrupt.?(interruptCause, finalCause)
    csr.tval := interrupt.?(0.U(32), finalTval)
    csr.mret := returning
    csr.retire := complete & !failed & !debugBreakpoint & !m.injected
    io.interrupt.valid := interrupt & !coreReset.asBool
    io.interrupt.pc := architecturalPc
    io.interrupt.target := csr.trapTarget
    io.interrupt.cause := interruptCause
    io.interrupt.userMode := csr.userMode
    io.interrupt.csrMstatus :<= csr.statusTrace
    io.interrupt.csrMepc :<= csr.epcTrace
    io.interrupt.csrMcause :<= csr.causeTrace
    io.interrupt.csrMtval :<= csr.valueTrace
    io.sleeping := sleeping
  private def injectExecution(debug: Interface[DebugHartIO], io: Interface[CoreIO],
      x: Reg[Instruction], xValid: Reg[Bool], xUser: Reg[Bool],
      xInjected: Reg[Bool], xSequence: Reg[UInt], xTruncated: Reg[Bool],
      m: Referable[Completion], mValid: Referable[Bool], complete: Referable[Bool], failed: Referable[Bool],
      actualWriteback: Referable[Bool], writeback: Referable[UInt], debugLocalSelected: Referable[Bool],
      debugStop: Referable[Bool], debugResume: Referable[Bool], coreReset: Referable[Reset])
      (using Arena, Context, Block, InstanceContext): Unit =
    debug.core.injection.ready := !xValid & !mValid & debugStop & !debugResume & !coreReset.asBool
    debug.core.injectedIdle := !(xValid & xInjected) & !(mValid & m.injected)
    debug.core.injectionDone.valid := complete & m.injected & !coreReset.asBool
    debug.core.injectionDone.sequence := m.injectedSequence
    debug.core.injectionDone.fault := complete & failed & m.injected
    debug.core.injectionDone.ebreak := complete & m.injectedBreak & !failed
    debug.core.localCsr.address := m.csrAddress
    debug.core.localCsr.operand := m.csrOperand
    debug.core.localCsr.operation := m.csrOperation
    debug.core.localCsr.writeRequested := m.csrWrite
    debug.core.localCsr.commit := complete & debugLocalSelected & m.csrWrite & !failed
    io.debugExecution.get.valid := complete & m.injected & !coreReset.asBool
    io.debugExecution.get.sequence := m.injectedSequence
    io.debugExecution.get.pc := m.instruction.pc
    io.debugExecution.get.word := m.instruction.word
    io.debugExecution.get.length := m.instruction.length
    io.debugExecution.get.rd := actualWriteback.?(m.rd, 0.U(5))
    io.debugExecution.get.writes := actualWriteback
    io.debugExecution.get.value := actualWriteback.?(writeback, 0.U(32))
    io.debugExecution.get.fault := complete & failed & m.injected
    io.debugExecution.get.ebreak := complete & m.injectedBreak & !failed
    io.debugExecution.get.csr := m.csr
    io.debugExecution.get.load := m.load
    io.debugExecution.get.store := m.store
    io.debugExecution.get.address := (m.load | m.store).?(m.address, 0.U(32))
    val injectionFire = debug.core.injection.valid & debug.core.injection.ready
    when(injectionFire) {
      xValid := true.B
      x.pc := (debug.core.injection.bits.sequence.asBits ## 0.B(1)).asUInt
      x.word := debug.core.injection.bits.word
      x.length := debug.core.injection.bits.length
      x.fault := false.B
      x.faultAddress := 0.U(32)
      xUser := false.B
      xInjected := true.B
      xSequence := debug.core.injection.bits.sequence
      xTruncated := debug.core.injection.bits.truncated
    }

  private def debugBackend(debug: Interface[DebugHartIO], csr: Interface[CsrIO], io: Interface[CoreIO],
      registers: Seq[Reg[UInt]], debugAccess: Referable[Bool], debugInjectionActive: Referable[Bool],
      debugDataOwner: Wire[Bool], programData: Wire[MemoryPort])
      (using Arena, Context, Block, InstanceContext): Unit =
    val register = debug.backend.register
    val gpr = (register >= 0x1000.U(16)) & (register <= 0x101f.U(16))
    val csrRegister = register <= 0x0fff.U(16)
    debug.backend.readData := csrRegister.?(csr.readData, 0.U(32))
    debug.backend.error := !(gpr | csrRegister) | (csrRegister & csr.illegal)
    for index <- 1 to 31 do
      when(register === (0x1000 + index).U(16)) {
        debug.backend.readData := registers(index - 1)
        when(debug.backend.writePulse) { registers(index - 1) := debug.backend.writeData }
      }
    when(debugAccess & !debugInjectionActive) {
      csr.address := register.asBits.bits(11, 0).asUInt
      csr.operand := debug.backend.writeData
      csr.operation := 1.U(2)
      csr.writeRequested := debug.backend.writeRequested
      csr.commit := debug.backend.writePulse & csrRegister
      csr.dataProtection.address := debug.protection.address
      csr.dataProtection.size := debug.protection.size
      csr.dataProtection.kind := debug.protection.write.?(1.U(2), 0.U(2))
    }
    debug.protection.allowed := csr.dataProtection.allowed
    debug.protection.machine := csr.dataMachine
    val debugMemory = debug.memory.request.valid | debug.memory.response.ready
    debugDataOwner := (debugAccess & !debugInjectionActive) | debugMemory
    debug.memory.request.ready := io.data.request.ready & debugMemory
    debug.memory.response.valid := io.data.response.valid & debugMemory
    debug.memory.response.bits :<= io.data.response.bits
    when(debugMemory) {
      io.data.request.valid := debug.memory.request.valid
      io.data.request.bits :<= debug.memory.request.bits
      io.data.response.ready := debug.memory.response.ready
      programData.request.ready := false.B
      programData.response.valid := false.B
    }

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
    val debugDataOwner = Wire(Bool())
    debugDataOwner := false.B
    val debugInjectionActive = Wire(Bool())
    debugInjectionActive := false.B
    val debugEntry = Wire(Bool())
    debugEntry := false.B
    val debugLocalRead = Wire(UInt(32))
    debugLocalRead := 0.U(32)
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
    val xInjected = RegInit(false.B)
    val xSequence = RegInit(0.U(3))
    val xTruncated = RegInit(false.B)
    val mValid = RegInit(false.B)
    val m = Reg(new Completion)
    val sent = RegInit(false.B)
    val architecturalPc = RegInit(BigInt(p.resetVector).U(32))
    val sleeping = RegInit(false.B)
    val registers = Seq.fill(31)(RegInit(0.U(32)))
    val retirementOrder = RegInit(0.U(64))
    val handlerPending = RegInit(false.B)

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
    csr.io.dataProtection.kind := (m.atomicOperation >= 3.U(4)).?(3.U(2), m.store.?(1.U(2), 0.U(2)))
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
    programData.request.bits.operation := m.atomicOperation
    programData.response.ready := mValid & memory & sent
    val response = programData.response.valid & programData.response.ready
    val debugLocalSelected = m.injected & m.csr & ((m.csrAddress === 0x7b0.U(12)) | (m.csrAddress === 0x7b1.U(12)))
    val csrError = m.csr & csr.io.illegal & !debugLocalSelected
    val protectionUpdate = mValid & m.csr & m.csrWrite & csr.io.protectionSelected & !csrError & !m.trap
    val synchronize = m.fenceI | protectionUpdate
    val synchronizing = mValid & synchronize & !m.trap
    val complete = mValid & (m.trap | denied | (!memory & (!synchronize | fetch.io.idle)) | response)
    val failed = m.trap | csrError | denied | (response & programData.response.bits.fault)
    val trap = complete & failed & !m.injected
    val returning = complete & m.mret & !failed
    val waiting = complete & m.wfi & !failed
    val synchronized = complete & synchronize & !failed & !m.injected
    val debugBreakpoint = complete & m.debugBreak & !failed
    val triggerInterrupt = localWake & csr.io.interruptsEnabled & !debugStep
    val (triggerMatched, triggerNative, triggerDebug) = triggerActions(p, csr.io, x, xValid, xInjected, xUser,
      debugAccess, mValid, triggerInterrupt, sleeping, debugResume, trap, interrupt, returning)
    if p.enableA then
      val permissionWrite = complete & m.csr & m.csrWrite & !failed &
        (csr.io.protectionSelected | (m.csrAddress === 0x300.U(12)))
      io.reservationClear.get := io.reset.asBool | systemReset | trap | interrupt | returning |
        permissionWrite | debugEntry | debugResume
      io.dataDebug.get := debugDataOwner
    val finalCause = m.trap.?(m.cause, csrError.?(2.U(32), m.store.?(7.U(32), 5.U(32))))
    val finalTval = m.trap.?(m.tval, csrError.?(m.instruction.word, m.address))
    driveTrap(csr.io, io, m, complete, failed, trap, interrupt, returning, debugBreakpoint,
      architecturalPc, interruptCause, finalCause, finalTval, coreReset, sleeping)
    val loaded = (programData.response.bits.data >> shift).asBits
    val loadValue = Wire(UInt(32))
    loadValue := loaded.asUInt
    when(m.size === 0.U(2)) {
      loadValue := ((loaded.bit(7) & !m.unsignedLoad).?(0xffffff.B(24), 0.B(24)) ## loaded.bits(7, 0)).asUInt
    }
    when(m.size === 1.U(2)) {
      loadValue := ((loaded.bit(15) & !m.unsignedLoad).?(0xffff.B(16), 0.B(16)) ## loaded.bits(15, 0)).asUInt
    }
    val writeback = m.csr.?(debugLocalSelected.?(debugLocalRead, csr.io.readData), m.load.?(loadValue, m.value))
    val actualWriteback = complete & !debugBreakpoint & !failed & m.writes & (m.rd =/= 0.U(5)) & !coreReset.asBool
    io.retire.valid := complete & !debugBreakpoint & !coreReset.asBool & !m.injected
    io.retire.userMode := m.userMode
    io.retire.pc := m.instruction.pc
    io.retire.word := m.instruction.word
    io.retire.nextPc := failed.?(csr.io.trapTarget, m.mret.?(csr.io.returnPc, m.nextPc))
    io.retire.rd := (actualWriteback & !m.injected).?(m.rd, 0.U(5))
    io.retire.writes := actualWriteback & !m.injected
    io.retire.value := io.retire.writes.?(writeback, 0.U(32))
    io.retire.trap := trap
    io.retire.cause := finalCause
    io.retire.tval := finalTval
    observeRetirement(() => {
      io.retire.order := retirementOrder
      io.retire.length := m.instruction.length
      io.retire.insn := m.instruction.fault.?(0.U(32),
        (m.instruction.length === 2.U(3)).?((0.B(16) ## m.instruction.word.asBits.bits(15, 0)).asUInt, m.instruction.word))
      io.retire.intr := handlerPending
      io.retire.rs1 := m.rs1
      io.retire.rs1Data := m.rs1Data
      io.retire.rs2 := m.rs2
      io.retire.rs2Data := m.rs2Data
      val accessFault = trap & ((finalCause === 1.U(32)) | (finalCause === 5.U(32)) | (finalCause === 7.U(32)))
      val fetchFault = trap & (finalCause === 1.U(32))
      val accessMask = (mask << lane).asBits.bits(3, 0).asUInt
      val conditionalStore = m.atomicOperation === 2.U(4)
      val atomicModify = m.atomicOperation >= 3.U(4)
      val successfulStore = m.store & !failed & (!conditionalStore | (programData.response.bits.data === 0.U(32)))
      io.retire.memoryAddress := (memory & !m.instruction.fault).?((m.address.asBits.bits(31, 2) ## 0.B(2)).asUInt, 0.U(32))
      io.retire.memoryReadMask := (memory & m.load & !conditionalStore & !failed).?(accessMask, 0.U(4))
      io.retire.memoryWriteMask := (successfulStore & !atomicModify).?(accessMask, 0.U(4))
      io.retire.memoryReadData := (io.retire.memoryReadMask =/= 0.U(4)).?(programData.response.bits.data, 0.U(32))
      io.retire.memoryWriteData := (memory & m.store & !failed).?(programData.request.bits.data, 0.U(32))
      io.retire.memoryOperation := (memory & !m.instruction.fault).?(m.atomicOperation, 0.U(4))
      io.retire.memoryResponse := response.?(programData.response.bits.data, 0.U(32))
      io.retire.memoryOperand := (memory & !m.instruction.fault & (m.atomicOperation =/= 0.U(4))).?(m.storeData, 0.U(32))
      io.retire.memoryFault := accessFault
      io.retire.faultReadMask := (accessFault & !fetchFault & m.load & !conditionalStore).?(accessMask, 0.U(4))
      io.retire.faultWriteMask := (accessFault & !fetchFault & m.store).?(accessMask, 0.U(4))
      io.retire.misa := csr.io.misa
      io.retire.csr.valid := m.csr & !failed
      io.retire.csr.address := m.csrAddress
      io.retire.csr.readMask := (m.csr & m.csrRead & !failed).?(0xffffffffL.U(32), 0.U(32))
      io.retire.csr.writeMask := (m.csr & !failed).?(csr.io.writeMask, 0.U(32))
      io.retire.csr.readData := csr.io.readData
      io.retire.csr.writeData := csr.io.writtenData
      io.retire.csrMstatus :<= csr.io.statusTrace
      io.retire.csrMepc :<= csr.io.epcTrace
      io.retire.csrMcause :<= csr.io.causeTrace
      io.retire.csrMtval :<= csr.io.valueTrace
      io.retire.csrCycle :<= csr.io.cycleTrace
      io.retire.csrInstret :<= csr.io.instretTrace
      io.retire.csrTime := io.timeValue
      when(io.retire.valid) {
        retirementOrder := (retirementOrder + 1.U(64)).asBits.bits(63, 0).asUInt
        handlerPending := false.B
      }
      when(trap | interrupt) { handlerPending := true.B }
    })
    when(complete & !debugBreakpoint & !m.injected) { architecturalPc := io.retire.nextPc }
    when(debugResume) { architecturalPc := debugResumePc }
    when(interrupt) { architecturalPc := csr.io.trapTarget }
    for i <- 1 to 31 do
      when(actualWriteback & (m.rd === i.U(5))) { registers(i - 1) := writeback }

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
    val isAtomic = Wire(Bool())
    val atomicOperation = Wire(UInt(4))
    val atomicFunction = bits.bits(31, 27)
    val isLr = atomicFunction === 2.B(5)
    isAtomic := false.B
    atomicOperation := 0.U(4)
    if p.enableA then
      val validFunction = Seq(0, 1, 2, 3, 4, 8, 12, 16, 20, 24, 28)
        .map(code => atomicFunction === code.B(5)).reduce(_ | _)
      isAtomic := (opcode === 0x2f.B(7)) & (funct3 === 2.B(3)) & validFunction &
        (!isLr | (rs2 === 0.U(5)))
      for (function, operation) <- Seq(2 -> 1, 3 -> 2, 1 -> 3, 0 -> 4, 4 -> 5,
          12 -> 6, 8 -> 7, 16 -> 8, 20 -> 9, 24 -> 10, 28 -> 11) do
        when(isAtomic & (atomicFunction === function.B(5))) { atomicOperation := operation.U(4) }
    val isBit = Wire(Bool())
    val bitUsesRs2 = Wire(Bool())
    val bitValue = Wire(UInt(32))
    isBit := false.B
    bitUsesRs2 := false.B
    bitValue := 0.U(32)
    val isLui = opcode === 0x37.B(7)
    val isAuipc = opcode === 0x17.B(7)
    val isLoad = (opcode === 0x03.B(7)) & ((funct3.asUInt <= 2.U(3)) |
      (funct3 === 4.B(3)) | (funct3 === 5.B(3)))
    val isStore = (opcode === 0x23.B(7)) & (funct3.asUInt <= 2.U(3))
    val isBranch = (opcode === 0x63.B(7)) & (funct3.bits(2, 1) =/= 1.B(2))
    val isJal = opcode === 0x6f.B(7)
    val isJalr = (opcode === 0x67.B(7)) & (funct3 === 0.B(3))
    val isBreak = decoded === 0x00100073.U(32)
    val isDebugBreak = isBreak & !xInjected & xUser.?(debugBreakUser, debugBreakMachine)
    val isCall = decoded === 0x00000073.U(32)
    val isFence = (opcode === 0x0f.B(7)) & (funct3 === 0.B(3))
    val isFenceI = (opcode === 0x0f.B(7)) & (funct3 === 1.B(3))
    val isCsr = (opcode === 0x73.B(7)) & (funct3.bits(1, 0) =/= 0.B(2))
    val isMret = decoded === 0x30200073.U(32)
    val isWfi = decoded === 0x10500073.U(32)
    val legal = encodingLegal & (isImmediate | isRegister | isMultiplyDivide | isBit | isAtomic | isLui | isAuipc | isLoad | isStore | isBranch | isJal | isJalr | isBreak | isCall | isFence | isFenceI | isCsr | isMret | isWfi)
    val use1 = isImmediate | isRegister | isMultiplyDivide | isBit | isAtomic | isLoad | isStore | isBranch | isJalr | (isCsr & !funct3.bit(2))
    val use2 = isRegister | isMultiplyDivide | bitUsesRs2 | (isAtomic & !isLr) | isStore | isBranch
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
    if p.enableZba || p.enableZbb || p.enableZbs then
      val bit = BitOperations.instantiate(BitParameters(p.enableZba, p.enableZbb, p.enableZbs))
      bit.io.word := decoded
      bit.io.a := a
      bit.io.b := b
      isBit := bit.io.valid
      bitUsesRs2 := bit.io.usesRs2
      bitValue := bit.io.result
    val loadUse = m.load & (match1 | match2)
    val serialM = mValid & (m.csr | m.mret | m.wfi | m.fenceI)
    val arithmeticReady = Wire(Bool())
    val arithmeticValue = Wire(UInt(32))
    arithmeticReady := true.B
    arithmeticValue := 0.U(32)
    val advance = triggerNative | (xValid & (!mValid | complete) & !loadUse & !trap & !serialM &
      (!(isCsr | isMret | isWfi | isFenceI) | !mValid) & !eligibleInterrupt & !sleeping &
      (!isMultiplyDivide | x.fault | arithmeticReady) & (!debugStop | xInjected) & !triggerMatched)
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
      multiplyDivide.io.cancel := trap | interrupt | (debugStop & !debugInjectionActive)
      multiplyDivide.io.request.valid := xValid & isMultiplyDivide & !arithmeticPending &
        !loadUse & !serialM & !trap & !eligibleInterrupt & !sleeping & !x.fault & (!debugStop | xInjected) & !triggerMatched
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
      io.mulDiv.cancel := arithmeticPending & (trap | interrupt | (debugStop & !debugInjectionActive))
      io.mulDiv.pc := x.pc
      io.mulDiv.value := multiplyDivide.io.response.valid.?(multiplyDivide.io.response.bits, 0.U(32))
      when(started) { arithmeticPending := true.B }
      when(finished | trap | interrupt | (debugStop & !debugInjectionActive)) { arithmeticPending := false.B }
    io.loadUse := xValid & loadUse
    io.forward := advance & !m.load & (match1 | match2)
    io.memoryWait := mValid & memory & !complete

    val sign = bits.bit(31)
    val immI = (sign.?(0xfffff.B(20), 0.B(20)) ## bits.bits(31, 20)).asUInt
    val immS = (sign.?(0xfffff.B(20), 0.B(20)) ## bits.bits(31, 25) ## bits.bits(11, 7)).asUInt
    val immB = (sign.?(0x7ffff.B(19), 0.B(19)) ## bits.bits(31, 31) ## bits.bits(7, 7) ## bits.bits(30, 25) ## bits.bits(11, 8) ## 0.B(1)).asUInt
    val immJ = (sign.?(0x7ff.B(11), 0.B(11)) ## bits.bits(31, 31) ## bits.bits(19, 12) ## bits.bits(20, 20) ## bits.bits(30, 21) ## 0.B(1)).asUInt
    val sequential = (x.pc + x.length).asBits.bits(31, 0).asUInt
    val address = isAtomic.?(a, (a + isStore.?(immS, immI)).asBits.bits(31, 0).asUInt)
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
    val badData = (isLoad | isStore | isAtomic) & (
      ((size === 2.U(2)) & (address.asBits.bits(1, 0) =/= 0.B(2))) |
      ((size === 1.U(2)) & address.asBits.bit(0)))
    val injectedControl = xInjected & (isBranch | isJal | isJalr | isAuipc | isMret | isFenceI)
    val systemFault = (isMret & xUser) | (isWfi & csr.io.wfiIllegal & !xInjected)
    val fault = triggerNative | x.fault | xTruncated | injectedControl | !legal |
      (isBreak & !xInjected & !isDebugBreak) | isCall | badTarget | badData | systemFault
    val cause = Wire(UInt(32))
    val tval = Wire(UInt(32))
    cause := 2.U(32)
    tval := x.word
    when(isBreak) { cause := 3.U(4); tval := x.pc }
    when(isCall) { cause := xUser.?(8.U(32), 11.U(32)); tval := 0.U(32) }
    when(badData) { cause := (isStore | (isAtomic & !isLr)).?(6.U(32), 4.U(32)); tval := address }
    when(badTarget) { cause := 0.U(32); tval := target }
    when(x.fault) { cause := 1.U(32); tval := x.faultAddress }
    when(triggerNative) { cause := 3.U(4); tval := x.pc }
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
    when(isBit) { value := bitValue }

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
      m.rs1 := (use1 & legal & !x.fault).?(rs1, 0.U(5))
      m.rs1Data := (use1 & legal & !x.fault).?(a, 0.U(32))
      m.rs2 := (use2 & legal & !x.fault).?(rs2, 0.U(5))
      m.rs2Data := (use2 & legal & !x.fault).?(b, 0.U(32))
      m.userMode := xUser
      m.debugBreak := isDebugBreak
      m.injected := xInjected
      m.injectedSequence := xSequence
      m.injectedBreak := xInjected & isBreak
      m.nextPc := jump.?(target, sequential)
      m.rd := bits.bits(11, 7).asUInt
      m.writes := isImmediate | isRegister | isMultiplyDivide | isBit | isAtomic | isLui | isAuipc | isLoad | isJal | isJalr | isCsr
      m.value := value
      m.load := isLoad | isAtomic
      m.store := isStore | (isAtomic & !isLr)
      m.atomicOperation := atomicOperation
      m.address := address
      m.storeData := b
      m.size := size
      m.unsignedLoad := funct3.bit(2)
      m.csr := isCsr
      m.csrAddress := bits.bits(31, 20).asUInt
      m.csrOperation := funct3.bits(1, 0).asUInt
      m.csrOperand := funct3.bit(2).?((0.B(27) ## bits.bits(19, 15)).asUInt, a)
      m.csrWrite := (funct3.bits(1, 0) === 1.B(2)) | (rs1 =/= 0.U(5))
      m.csrRead := isCsr & ((funct3.bits(1, 0) =/= 1.B(2)) | (bits.bits(11, 7) =/= 0.B(5)))
      m.mret := isMret
      m.wfi := isWfi & !xInjected
      m.fenceI := isFenceI
      m.trap := fault
      m.cause := cause
      m.tval := tval
    }
    when(fetch.io.output.valid & fetch.io.output.ready) {
      xValid := true.B
      x :<= fetch.io.output.bits
      xUser := csr.io.userMode
      xInjected := false.B
      xSequence := 0.U(3)
      xTruncated := false.B
    }
    when(waiting) { sleeping := !localWake & !debugStep }
    when(waking | trap | interrupt | debugStop | debugResume) { sleeping := false.B }
    when(trap | interrupt | returning | waiting | waking | synchronized) { xValid := false.B; mValid := false.B }
    when(debugResume | (debugStop & !xInjected)) { xValid := false.B }
    if p.enableDebug then
      val dm = DebugModule.instantiate(p)
      val debug = DebugHart.instantiate(DebugHartParameters(p.resetVector, p.enableC, p.protectedMode))
      dm.io.clock := io.clock
      dm.io.reset := io.reset
      if p.enableJtag then DitDahE2DebugTransport.connect(p, io.clock, io.reset, io.jtag.get, dm.io.dmi)
      else dm.io.dmi :<>= io.dmi.get
      debug.io.clock := io.clock
      debug.io.reset := io.reset
      debug.io.debug :<>= dm.io.hart
      debug.io.core.empty := !mValid
      debug.io.core.fetchIdle := fetch.io.idle
      debug.io.core.architecturalPc := architecturalPc
      debug.io.core.userMode := csr.io.userMode
      debug.io.core.completed := complete & !debugBreakpoint & !m.injected
      debug.io.core.breakpoint := debugBreakpoint | triggerDebug
      debug.io.core.breakpointPc := triggerDebug.?(x.pc, m.instruction.pc)
      debugStop := debug.io.core.stop
      debugResume := debug.io.core.resume
      debugResumePc := debug.io.core.resumePc
      debugResumeUser := debug.io.core.resumeUser
      debugStep := debug.io.core.singleStep
      debugFreeze := debug.io.core.freezeCounters
      debugAccess := debug.io.debug.status.halted
      debugBreakMachine := debug.io.core.ebreakMachine
      debugBreakUser := debug.io.core.ebreakUser
      debugInjectionActive := debug.io.core.injectionActive
      debugEntry := debug.io.core.entry
      debugLocalRead := debug.io.core.localCsr.readData
      systemReset := debug.io.core.coreReset
      io.systemReset.get := systemReset
      injectExecution(debug.io, io, x, xValid, xUser, xInjected, xSequence, xTruncated, m, mValid,
        complete, failed, actualWriteback, writeback, debugLocalSelected, debugStop, debugResume, coreReset)
      debugBackend(debug.io, csr.io, io, registers, debugAccess, debugInjectionActive, debugDataOwner, programData)
