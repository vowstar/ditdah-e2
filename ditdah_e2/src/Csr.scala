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
    val status = if p.protectedMode then
      (0.B(10) ## tw.asBits ## 0.B(3) ## mprv.asBits ## 0.B(4) ##
        mppUser.?(0.B(2), 3.B(2)) ## 0.B(3) ## mpie.asBits ## 0.B(3) ## mie.asBits ## 0.B(3)).asUInt
    else (0.B(19) ## 3.B(2) ## 0.B(3) ## mpie.asBits ## 0.B(3) ## mie.asBits ## 0.B(3)).asUInt
    val named = Seq(0x300, 0x301, 0x304, 0x305, 0x310, 0x320, 0x340, 0x341,
      0x342, 0x343, 0x344, 0xb00, 0xb80, 0xb02, 0xb82,
      0xc00, 0xc80, 0xc01, 0xc81, 0xc02, 0xc82, 0xf11, 0xf12, 0xf13, 0xf14, 0xf15)
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
        mie := writeData.asBits.bit(3)
        mpie := writeData.asBits.bit(7)
        if p.protectedMode then
          mppUser := writeData.asBits.bits(12, 11) === 0.B(2)
          mprv := writeData.asBits.bit(17)
          tw := writeData.asBits.bit(21)
      }
      when(counterAccess) { counterEnable := writeData.asBits.bits(2, 0).asUInt }
      when(io.address === 0x304.U(12)) { interruptEnables := (writeData.asBits.bits(11, 0) & 0x888.B(12)).asUInt }
      when(io.address === 0x305.U(12)) {
        mtvec := (writeData.asBits.bits(31, 2) ## 0.B(1) ## (writeData.asBits.bits(1, 0) === 1.B(2)).asBits).asUInt
      }
      when(io.address === 0x320.U(12)) { inhibit := (writeData.asBits.bits(2, 0) & 5.B(3)).asUInt }
      when(io.address === 0x340.U(12)) { mscratch := writeData }
      when(io.address === 0x341.U(12)) {
        mepc := (if p.enableC then writeData.asBits.bits(31, 1) ## 0.B(1) else writeData.asBits.bits(31, 2) ## 0.B(2)).asUInt
      }
      when(io.address === 0x342.U(12)) { mcause := writeData }
      when(io.address === 0x343.U(12)) { mtval := writeData }
    }
    when(io.mret & !io.trap) {
      mie := mpie
      mpie := true.B
      if p.protectedMode then
        userMode := mppUser
        mppUser := true.B
        when(mppUser) { mprv := false.B }
    }
    if p.protectedMode then
      when(io.debugRestore) {
        userMode := io.debugUser
        when(io.debugUser) { mprv := false.B }
      }
    when(io.trap) {
      mie := false.B
      mpie := mie
      if p.protectedMode then
        mppUser := userMode
        userMode := false.B
      mepc := (if p.enableC then io.trapPc.asBits.bits(31, 1) ## 0.B(1) else io.trapPc.asBits.bits(31, 2) ## 0.B(2)).asUInt
      mcause := io.cause
      mtval := io.tval
    }
