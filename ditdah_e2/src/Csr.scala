// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class CsrIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val address = Flipped(UInt(12))
  val operand = Flipped(UInt(32))
  val operation = Flipped(UInt(2))
  val writeRequested = Flipped(Bool())
  val commit = Flipped(Bool())
  val trap = Flipped(Bool())
  val trapPc = Flipped(UInt(32))
  val cause = Flipped(UInt(32))
  val tval = Flipped(UInt(32))
  val mret = Flipped(Bool())
  val retire = Flipped(Bool())
  val debugAccess = Flipped(Bool())
  val debugHalted = Flipped(Bool())
  val debugRestore = Flipped(Bool())
  val debugUser = Flipped(Bool())
  val interrupts = Flipped(new InterruptLevels)
  val timeValue = Flipped(UInt(64))
  val readData = Aligned(UInt(32))
  val writeMask = Aligned(UInt(32))
  val writtenData = Aligned(UInt(32))
  val misa = Aligned(UInt(32))
  val statusTrace = Aligned(new CsrState)
  val epcTrace = Aligned(new CsrState)
  val causeTrace = Aligned(new CsrState)
  val valueTrace = Aligned(new CsrState)
  val cycleTrace = Aligned(new CsrState(64))
  val instretTrace = Aligned(new CsrState(64))
  val illegal = Aligned(Bool())
  val trapTarget = Aligned(UInt(32))
  val returnPc = Aligned(UInt(32))
  val interruptPending = Aligned(UInt(12))
  val interruptsEnabled = Aligned(Bool())
  val userMode = Aligned(Bool())
  val dataMachine = Aligned(Bool())
  val wfiIllegal = Aligned(Bool())
  val protectionSelected = Aligned(Bool())
  val instructionProtection = Aligned(new PmpAccess)
  val dataProtection = Aligned(new PmpAccess)

@generator
object Csr extends Generator[Parameters, UnitLayers, CsrIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2Csr"
  def architecture(p: Parameters) =
    val io = summon[Interface[CsrIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val mie = RegInit(false.B)
    val mpie = RegInit(false.B)
    val userMode = RegInit(false.B)
    val mppUser = RegInit(false.B)
    val mprv = RegInit(false.B)
    val tw = RegInit(false.B)
    val counterEnable = RegInit(0.U(3))
    io.userMode := (if p.protectedMode then userMode else false.B)
    io.dataMachine := (if p.protectedMode then (!userMode | io.debugAccess) & !(mprv & mppUser) else true.B)
    io.wfiIllegal := (if p.protectedMode then userMode & tw else false.B)
    val protectionRead = Wire(UInt(32))
    val protectionWrite = Wire(Bool())
    val protectionWriteData = Wire(UInt(32))
    val protectionMask = Wire(UInt(32))
    val protectionAfter = Wire(UInt(32))
    protectionMask := 0.U(32)
    protectionAfter := 0.U(32)
    protectionRead := 0.U(32)
    io.protectionSelected := false.B
    if p.protectedMode then
      val pmp = Pmp.instantiate(p)
      pmp.io.clock := io.clock
      pmp.io.reset := io.reset
      pmp.io.address := io.address
      pmp.io.commitWrite := protectionWrite
      pmp.io.writeData := protectionWriteData
      io.instructionProtection :<>= pmp.io.instruction
      io.dataProtection :<>= pmp.io.data
      io.protectionSelected := pmp.io.implemented
      protectionRead := pmp.io.readData
      protectionMask := pmp.io.writeMask
      protectionAfter := pmp.io.writtenData
    else
      io.instructionProtection.allowed := true.B
      io.dataProtection.allowed := true.B
    val interruptEnables = RegInit(0.U(12))
    val inhibit = RegInit(0.U(3))
    val counters = Counters.instantiate(p)
    counters.io.clock := io.clock
    counters.io.reset := io.reset
    counters.io.retire := io.retire
    counters.io.inhibit := (inhibit.asBits | io.debugHalted.?(5.B(3), 0.B(3))).asUInt
    counters.io.high := io.address.asBits.bit(7)
    val mtvec = RegInit(BigInt(p.resetVector & 0xfffffffcL).U(32))
    val mscratch = RegInit(0.U(32))
    val mepc = RegInit(0.U(32))
    val mcause = RegInit(0.U(32))
    val mtval = RegInit(0.U(32))
    val mieNext = Wire(Bool())
    mieNext := mie
    val mpieNext = Wire(Bool())
    mpieNext := mpie
    val userModeNext = Wire(Bool())
    userModeNext := userMode
    val mppUserNext = Wire(Bool())
    mppUserNext := mppUser
    val mprvNext = Wire(Bool())
    mprvNext := mprv
    val twNext = Wire(Bool())
    twNext := tw
    val counterEnableNext = Wire(UInt(3))
    counterEnableNext := counterEnable
    val interruptEnablesNext = Wire(UInt(12))
    interruptEnablesNext := interruptEnables
    val inhibitNext = Wire(UInt(3))
    inhibitNext := inhibit
    val mtvecNext = Wire(UInt(32))
    mtvecNext := mtvec
    val mscratchNext = Wire(UInt(32))
    mscratchNext := mscratch
    val mepcNext = Wire(UInt(32))
    mepcNext := mepc
    val mcauseNext = Wire(UInt(32))
    mcauseNext := mcause
    val mtvalNext = Wire(UInt(32))
    mtvalNext := mtval
    val status = if p.protectedMode then
      (0.B(10) ## tw.asBits ## 0.B(3) ## mprv.asBits ## 0.B(4) ##
        mppUser.?(0.B(2), 3.B(2)) ## 0.B(3) ## mpie.asBits ## 0.B(3) ## mie.asBits ## 0.B(3)).asUInt
    else (0.B(19) ## 3.B(2) ## 0.B(3) ## mpie.asBits ## 0.B(3) ## mie.asBits ## 0.B(3)).asUInt
    val named = (Seq(0x300, 0x301, 0x304, 0x305, 0x310, 0x320, 0x340, 0x341,
      0x342, 0x343, 0x344, 0xb00, 0xb80, 0xb02, 0xb82,
      0xc00, 0xc80, 0xc01, 0xc81, 0xc02, 0xc82, 0xf11, 0xf12, 0xf13, 0xf14, 0xf15) ++
      (if p.protectedMode then Seq(0x30a, 0x31a) else Seq.empty))
      .map(address => io.address === address.U(12)).reduce(_ | _)
    val zeroCounter = ((io.address >= 0xb03.U(12)) & (io.address <= 0xb1f.U(12))) |
      ((io.address >= 0xb83.U(12)) & (io.address <= 0xb9f.U(12))) |
      ((io.address >= 0x323.U(12)) & (io.address <= 0x33f.U(12)))
    val counterAccess = if p.protectedMode then io.address === 0x306.U(12) else false.B
    val implemented = named | zeroCounter | io.protectionSelected | counterAccess
    val pending = (io.interrupts.external.asBits ## 0.B(3) ## io.interrupts.timer.asBits ##
      0.B(3) ## io.interrupts.software.asBits ## 0.B(3)).asUInt
    io.interruptPending := (pending.asBits & interruptEnables.asBits).asUInt
    io.interruptsEnabled := mie | io.userMode
    val readOnly = io.address.asBits.bits(11, 10) === 3.B(2)
    val userCounterDenied = Wire(Bool())
    userCounterDenied := false.B
    if p.protectedMode then
      for index <- 0 until 3 do
        when((io.address === (0xc00 + index).U(12)) | (io.address === (0xc80 + index).U(12))) {
          userCounterDenied := !counterEnable.asBits.bit(index)
        }
    io.illegal := !implemented | (io.writeRequested & readOnly) |
      (io.userMode & !io.debugAccess & ((io.address.asBits.bits(9, 8) =/= 0.B(2)) | userCounterDenied))
    io.readData := 0.U(32)
    when(io.address === 0x300.U(12)) { io.readData := status }
    val misa = 0x40000100L | (if p.enableA then 1L else 0L) | (if p.enableM then 0x1000L else 0L) | (if p.enableC then 4L else 0L) |
      (if p.enableZba && p.enableZbb && p.enableZbs then 2L else 0L) |
      (if p.protectedMode then 0x100000L else 0L)
    io.misa := misa.U(32)
    when(io.address === 0x301.U(12)) { io.readData := misa.U(32) }
    when(io.address === 0x304.U(12)) { io.readData := interruptEnables }
    when(io.address === 0x305.U(12)) { io.readData := mtvec }
    when(io.address === 0x340.U(12)) { io.readData := mscratch }
    when(io.address === 0x341.U(12)) { io.readData := mepc }
    when(io.address === 0x342.U(12)) { io.readData := mcause }
    when(io.address === 0x343.U(12)) { io.readData := mtval }
    when(io.address === 0x344.U(12)) { io.readData := pending }
    when(io.address === 0x320.U(12)) { io.readData := inhibit }
    when(counterAccess) { io.readData := counterEnable }
    when(io.protectionSelected) { io.readData := protectionRead }
    for address <- Seq(0xb00, 0xc00) do
      when(io.address === address.U(12)) { io.readData := counters.io.cycleCount.asBits.bits(31, 0).asUInt }
    for address <- Seq(0xb80, 0xc80) do
      when(io.address === address.U(12)) { io.readData := counters.io.cycleCount.asBits.bits(63, 32).asUInt }
    for address <- Seq(0xb02, 0xc02) do
      when(io.address === address.U(12)) { io.readData := counters.io.instretCount.asBits.bits(31, 0).asUInt }
    for address <- Seq(0xb82, 0xc82) do
      when(io.address === address.U(12)) { io.readData := counters.io.instretCount.asBits.bits(63, 32).asUInt }
    when(io.address === 0xc01.U(12)) { io.readData := io.timeValue.asBits.bits(31, 0).asUInt }
    when(io.address === 0xc81.U(12)) { io.readData := io.timeValue.asBits.bits(63, 32).asUInt }
    val vectorBase = (mtvec.asBits.bits(31, 2) ## 0.B(2)).asUInt
    val vectorOffset = (io.cause.asBits.bits(29, 0) ## 0.B(2)).asUInt
    io.trapTarget := (mtvec.asBits.bit(0) & io.cause.asBits.bit(31)).?(
      (vectorBase + vectorOffset).asBits.bits(31, 0).asUInt, vectorBase)
    io.returnPc := mepc

    val writeData = Wire(UInt(32))
    writeData := io.operand
    when(io.operation === 2.U(2)) { writeData := (io.readData.asBits | io.operand.asBits).asUInt }
    when(io.operation === 3.U(2)) { writeData := (io.readData.asBits & ~io.operand.asBits).asUInt }
    counters.io.writeData := writeData
    val write = io.commit & io.writeRequested & !io.illegal & !io.trap & !io.mret
    protectionWrite := write
    protectionWriteData := writeData
    counters.io.writeCycle := write & ((io.address === 0xb00.U(12)) | (io.address === 0xb80.U(12)))
    counters.io.writeInstret := write & ((io.address === 0xb02.U(12)) | (io.address === 0xb82.U(12)))
    when(write) {
      when(io.address === 0x300.U(12)) {
        mieNext := writeData.asBits.bit(3)
        mpieNext := writeData.asBits.bit(7)
        if p.protectedMode then
          mppUserNext := writeData.asBits.bits(12, 11) === 0.B(2)
          mprvNext := writeData.asBits.bit(17)
          twNext := writeData.asBits.bit(21)
      }
      when(counterAccess) { counterEnableNext := writeData.asBits.bits(2, 0).asUInt }
      when(io.address === 0x304.U(12)) { interruptEnablesNext := (writeData.asBits.bits(11, 0) & 0x888.B(12)).asUInt }
      when(io.address === 0x305.U(12)) {
        mtvecNext := (writeData.asBits.bits(31, 2) ## 0.B(1) ## (writeData.asBits.bits(1, 0) === 1.B(2)).asBits).asUInt
      }
      when(io.address === 0x320.U(12)) { inhibitNext := (writeData.asBits.bits(2, 0) & 5.B(3)).asUInt }
      when(io.address === 0x340.U(12)) { mscratchNext := writeData }
      when(io.address === 0x341.U(12)) {
        mepcNext := (if p.enableC then writeData.asBits.bits(31, 1) ## 0.B(1) else writeData.asBits.bits(31, 2) ## 0.B(2)).asUInt
      }
      when(io.address === 0x342.U(12)) { mcauseNext := writeData }
      when(io.address === 0x343.U(12)) { mtvalNext := writeData }
    }
    when(io.mret & !io.trap) {
      mieNext := mpie
      mpieNext := true.B
      if p.protectedMode then
        userModeNext := mppUser
        mppUserNext := true.B
        when(mppUser) { mprvNext := false.B }
    }
    if p.protectedMode then
      when(io.debugRestore) {
        userModeNext := io.debugUser
        when(io.debugUser) { mprvNext := false.B }
      }
    when(io.trap) {
      mieNext := false.B
      mpieNext := mie
      if p.protectedMode then
        mppUserNext := userMode
        userModeNext := false.B
      mepcNext := (if p.enableC then io.trapPc.asBits.bits(31, 1) ## 0.B(1) else io.trapPc.asBits.bits(31, 2) ## 0.B(2)).asUInt
      mcauseNext := io.cause
      mtvalNext := io.tval
    }

    mie := mieNext
    mpie := mpieNext
    userMode := userModeNext
    mppUser := mppUserNext
    mprv := mprvNext
    tw := twNext
    counterEnable := counterEnableNext
    interruptEnables := interruptEnablesNext
    inhibit := inhibitNext
    mtvec := mtvecNext
    mscratch := mscratchNext
    mepc := mepcNext
    mcause := mcauseNext
    mtval := mtvalNext


    val nextStatus = if p.protectedMode then
      (0.B(10) ## twNext.asBits ## 0.B(3) ## mprvNext.asBits ## 0.B(4) ##
        mppUserNext.?(0.B(2), 3.B(2)) ## 0.B(3) ## mpieNext.asBits ## 0.B(3) ## mieNext.asBits ## 0.B(3)).asUInt
    else (0.B(19) ## 3.B(2) ## 0.B(3) ## mpieNext.asBits ## 0.B(3) ## mieNext.asBits ## 0.B(3)).asUInt
    io.statusTrace.before := status
    io.statusTrace.after := nextStatus
    io.statusTrace.writeMask := 0.U(32)
    io.epcTrace.before := mepc
    io.epcTrace.after := mepcNext
    io.epcTrace.writeMask := 0.U(32)
    io.causeTrace.before := mcause
    io.causeTrace.after := mcauseNext
    io.causeTrace.writeMask := 0.U(32)
    io.valueTrace.before := mtval
    io.valueTrace.after := mtvalNext
    io.valueTrace.writeMask := 0.U(32)
    io.cycleTrace.before := counters.io.cycleCount
    io.cycleTrace.after := counters.io.cycleCount
    io.cycleTrace.writeMask := 0.U(64)
    io.instretTrace.before := counters.io.instretCount
    io.instretTrace.after := counters.io.instretCount
    io.instretTrace.writeMask := 0.U(64)
    io.writeMask := 0.U(32)
    io.writtenData := io.readData
    val epcMask = (if p.enableC then 0xfffffffeL else 0xfffffffcL).U(32)
    val statusMask = (if p.protectedMode then 0x221888L else 0x88L).U(32)
    when(write) {
      when(io.address === 0x300.U(12)) {
        io.writeMask := statusMask
        io.writtenData := nextStatus
        io.statusTrace.writeMask := statusMask
      }
      when(io.address === 0x304.U(12)) { io.writeMask := 0x888.U(32); io.writtenData := interruptEnablesNext }
      when(io.address === 0x305.U(12)) { io.writeMask := 0xfffffffdL.U(32); io.writtenData := mtvecNext }
      when(io.address === 0x320.U(12)) { io.writeMask := 5.U(32); io.writtenData := inhibitNext }
      when(counterAccess) { io.writeMask := 7.U(32); io.writtenData := counterEnableNext }
      when(io.address === 0x340.U(12)) { io.writeMask := 0xffffffffL.U(32); io.writtenData := mscratchNext }
      when(io.address === 0x341.U(12)) {
        io.writeMask := epcMask
        io.writtenData := mepcNext
        io.epcTrace.writeMask := epcMask
      }
      when(io.address === 0x342.U(12)) {
        io.writeMask := 0xffffffffL.U(32)
        io.writtenData := mcauseNext
        io.causeTrace.writeMask := 0xffffffffL.U(32)
      }
      when(io.address === 0x343.U(12)) {
        io.writeMask := 0xffffffffL.U(32)
        io.writtenData := mtvalNext
        io.valueTrace.writeMask := 0xffffffffL.U(32)
      }
      when(io.protectionSelected) { io.writeMask := protectionMask; io.writtenData := protectionAfter }
      when(counters.io.writeCycle | counters.io.writeInstret) {
        io.writeMask := 0xffffffffL.U(32)
        io.writtenData := writeData
      }
    }
    val counterMask = counters.io.high.?(BigInt("ffffffff00000000", 16).U(64), 0xffffffffL.U(64))
    when(counters.io.writeCycle) {
      io.cycleTrace.writeMask := counterMask
      io.cycleTrace.after := counters.io.high.?(
        (writeData.asBits ## counters.io.cycleCount.asBits.bits(31, 0)).asUInt,
        (counters.io.cycleCount.asBits.bits(63, 32) ## writeData.asBits).asUInt)
    }
    when(counters.io.writeInstret) {
      io.instretTrace.writeMask := counterMask
      io.instretTrace.after := counters.io.high.?(
        (writeData.asBits ## counters.io.instretCount.asBits.bits(31, 0)).asUInt,
        (counters.io.instretCount.asBits.bits(63, 32) ## writeData.asBits).asUInt)
    }
    when(io.mret & !io.trap) {
      io.statusTrace.writeMask := (if p.protectedMode then
        (0x1888.B(32) | mppUser.?(0x20000.B(32), 0.B(32))).asUInt else 0x88.U(32))
    }
    if p.protectedMode then
      when(io.debugRestore & io.debugUser) { io.statusTrace.writeMask := 0x20000.U(32) }
    when(io.trap) {
      io.statusTrace.writeMask := (if p.protectedMode then 0x1888L else 0x88L).U(32)
      io.epcTrace.writeMask := epcMask
      io.causeTrace.writeMask := 0xffffffffL.U(32)
      io.valueTrace.writeMask := 0xffffffffL.U(32)
    }
