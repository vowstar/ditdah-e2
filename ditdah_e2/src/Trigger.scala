// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class TriggerCorePort extends Bundle:
  val pc = Flipped(UInt(32))
  val valid = Flipped(Bool())
  val user = Flipped(Bool())
  val debug = Flipped(Bool())
  val ready = Flipped(Bool())
  val trap = Flipped(Bool())
  val mret = Flipped(Bool())
  val matched = Aligned(Bool())
  val debugAction = Aligned(Bool())
  val nativeAction = Aligned(Bool())

class TriggerObservation extends Bundle:
  val selected = Aligned(Bool())
  val dmode = Aligned(UInt(2))
  val hit = Aligned(UInt(2))
  val debugAction = Aligned(UInt(2))
  val machine = Aligned(UInt(2))
  val user = Aligned(UInt(2))
  val execute = Aligned(UInt(2))
  val address0 = Aligned(UInt(32))
  val address1 = Aligned(UInt(32))
  val mte = Aligned(Bool())
  val mpte = Aligned(Bool())

class TriggerIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val address = Flipped(UInt(12))
  val operand = Flipped(UInt(32))
  val operation = Flipped(UInt(2))
  val writeRequested = Flipped(Bool())
  val commit = Flipped(Bool())
  val debugAccess = Flipped(Bool())
  val implemented = Aligned(Bool())
  val readData = Aligned(UInt(32))
  val writeMask = Aligned(UInt(32))
  val writtenData = Aligned(UInt(32))
  val core = Aligned(new TriggerCorePort)
  val observe = Aligned(new TriggerObservation)

@generator
object DitDahE2Trigger extends Generator[Parameters, UnitLayers, TriggerIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2Trigger"
  def architecture(p: Parameters) =
    require(p.triggerCount == 2, "Trigger module requires two triggers")
    val io = summon[Interface[TriggerIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val selected = RegInit(false.B)
    val dmode = Seq.fill(2)(RegInit(false.B))
    val hit = Seq.fill(2)(RegInit(false.B))
    val debugAction = Seq.fill(2)(RegInit(false.B))
    val machine = Seq.fill(2)(RegInit(false.B))
    val user = Seq.fill(2)(RegInit(false.B))
    val execute = Seq.fill(2)(RegInit(false.B))
    val address = Seq.fill(2)(RegInit(0.U(32)))
    val mte = RegInit(false.B)
    val mpte = RegInit(false.B)
    io.observe.selected := selected
    io.observe.dmode := (dmode(1).asBits ## dmode(0).asBits).asUInt
    io.observe.hit := (hit(1).asBits ## hit(0).asBits).asUInt
    io.observe.debugAction := (debugAction(1).asBits ## debugAction(0).asBits).asUInt
    io.observe.machine := (machine(1).asBits ## machine(0).asBits).asUInt
    io.observe.user := (user(1).asBits ## user(0).asBits).asUInt
    io.observe.execute := (execute(1).asBits ## execute(0).asBits).asUInt
    io.observe.address0 := address(0)
    io.observe.address1 := address(1)
    io.observe.mte := mte
    io.observe.mpte := mpte

    val selectedAddress = Seq(0x7a0, 0x7a1, 0x7a2, 0x7a3, 0x7a4, 0x7a5, 0x7a8, 0x7aa)
      .map(value => io.address === value.U(12)).reduce(_ | _)
    io.implemented := selectedAddress
    io.readData := 0.U(32)
    io.writeMask := 0.U(32)
    io.writtenData := 0.U(32)
    when(io.address === 0x7a0.U(12)) { io.readData := (0.B(31) ## selected.asBits).asUInt }
    when(io.address === 0x7a1.U(12)) {
      io.readData := 0x20000000.U(32)
      io.writeMask := 0x0810104cL.U(32)
      for index <- 0 until 2 do
        when(selected === (index == 1).B) {
          io.readData := (2.B(4) ## dmode(index).asBits ## 0.B(6) ## hit(index).asBits ##
            0.B(4) ## (0.B(3) ## debugAction(index).asBits) ## 0.B(5) ## machine(index).asBits ##
            0.B(2) ## user(index).asBits ## execute(index).asBits ## 0.B(2)).asUInt
        }
    }
    when(io.address === 0x7a2.U(12)) {
      io.writeMask := 0xffffffffL.U(32)
      for index <- 0 until 2 do
        when(selected === (index == 1).B) { io.readData := address(index) }
    }
    when(io.address === 0x7a4.U(12)) { io.readData := 0x01000004.U(32) }
    when(io.address === 0x7a5.U(12)) {
      io.readData := (mpte.asBits ## 0.B(3) ## mte.asBits ## 0.B(3)).asUInt
      io.writeMask := 0x88.U(32)
    }
    io.writtenData := io.readData

    val writeData = Wire(UInt(32))
    writeData := io.operand
    when(io.operation === 2.U(2)) { writeData := (io.readData.asBits | io.operand.asBits).asUInt }
    when(io.operation === 3.U(2)) { writeData := (io.readData.asBits & ~io.operand.asBits).asUInt }
    val write = io.commit & io.writeRequested & selectedAddress
    when(write & (io.address === 0x7a0.U(12))) {
      selected := writeData.asBits.bit(0)
      io.writtenData := (0.B(31) ## writeData.asBits.bit(0).asBits).asUInt
    }
    when(write & (io.address === 0x7a5.U(12))) {
      mte := writeData.asBits.bit(3)
      mpte := writeData.asBits.bit(7)
      io.writtenData := (writeData.asBits & 0x88.B(8)).asUInt
    }
    for index <- 0 until 2 do
      val enabled = write & (selected === (index == 1).B) & !(dmode(index) & !io.debugAccess)
      when(enabled & (io.address === 0x7a1.U(12))) {
        hit(index) := writeData.asBits.bit(20)
        machine(index) := writeData.asBits.bit(6)
        user(index) := writeData.asBits.bit(3)
        execute(index) := writeData.asBits.bit(2)
        val nextDmode = io.debugAccess.?(writeData.asBits.bit(27), dmode(index))
        val nextAction = nextDmode & (writeData.asBits.bits(15, 12) === 1.B(4))
        debugAction(index) := nextAction
        when(io.debugAccess) { dmode(index) := nextDmode }
        io.writtenData := (2.B(4) ## nextDmode.asBits ## 0.B(6) ## writeData.asBits.bit(20).asBits ##
          0.B(4) ## (0.B(3) ## nextAction.asBits) ## 0.B(5) ## writeData.asBits.bit(6).asBits ##
          0.B(2) ## writeData.asBits.bit(3).asBits ## writeData.asBits.bit(2).asBits ## 0.B(2)).asUInt
      }
      when(enabled & (io.address === 0x7a2.U(12))) {
        address(index) := writeData
        io.writtenData := writeData
      }

    val matches = (0 until 2).map { index =>
      val privilege = io.core.user.?(user(index), machine(index))
      val nativeEnabled = io.core.user | debugAction(index) | mte
      io.core.valid & !io.core.debug & execute(index) & privilege & nativeEnabled &
        (io.core.pc === address(index))
    }
    io.core.matched := matches.reduce(_ | _)
    io.core.debugAction := io.core.ready & matches.zipWithIndex.map { case (matched, index) =>
      matched & debugAction(index)
    }.reduce(_ | _)
    io.core.nativeAction := io.core.ready & matches.reduce(_ | _) & !io.core.debugAction
    for index <- 0 until 2 do
      when(io.core.ready & matches(index)) { hit(index) := true.B }

    when(io.core.mret) {
      mte := mpte
    }
    when(io.core.trap) {
      mpte := mte
      mte := false.B
    }
