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
  val readData = Aligned(UInt(32))
  val illegal = Aligned(Bool())
  val trapTarget = Aligned(UInt(32))
  val returnPc = Aligned(UInt(32))

@generator
object Csr extends Generator[Parameters, UnitLayers, CsrIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2Csr"
  def architecture(p: Parameters) =
    val io = summon[Interface[CsrIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val mie = RegInit(false.B)
    val mpie = RegInit(false.B)
    val mtvec = RegInit(BigInt(p.resetVector & 0xfffffffcL).U(32))
    val mscratch = RegInit(0.U(32))
    val mepc = RegInit(0.U(32))
    val mcause = RegInit(0.U(32))
    val mtval = RegInit(0.U(32))
    val status = (0.B(19) ## 3.B(2) ## 0.B(3) ## mpie.asBits ## 0.B(3) ## mie.asBits ## 0.B(3)).asUInt
    val implemented = Seq(0x300, 0x301, 0x304, 0x305, 0x310, 0x340, 0x341,
      0x342, 0x343, 0x344, 0xf11, 0xf12, 0xf13, 0xf14, 0xf15)
      .map(address => io.address === address.U(12)).reduce(_ | _)
    val readOnly = io.address.asBits.bits(11, 10) === 3.B(2)
    io.illegal := !implemented | (io.writeRequested & readOnly)
    io.readData := 0.U(32)
    when(io.address === 0x300.U(12)) { io.readData := status }
    when(io.address === 0x301.U(12)) { io.readData := 0x40000100.U(32) }
    when(io.address === 0x305.U(12)) { io.readData := mtvec }
    when(io.address === 0x340.U(12)) { io.readData := mscratch }
    when(io.address === 0x341.U(12)) { io.readData := mepc }
    when(io.address === 0x342.U(12)) { io.readData := mcause }
    when(io.address === 0x343.U(12)) { io.readData := mtval }
    io.trapTarget := mtvec
    io.returnPc := mepc

    val writeData = Wire(UInt(32))
    writeData := io.operand
    when(io.operation === 2.U(2)) { writeData := (io.readData.asBits | io.operand.asBits).asUInt }
    when(io.operation === 3.U(2)) { writeData := (io.readData.asBits & ~io.operand.asBits).asUInt }
    when(io.commit & io.writeRequested & !io.illegal & !io.trap & !io.mret) {
      when(io.address === 0x300.U(12)) {
        mie := writeData.asBits.bit(3)
        mpie := writeData.asBits.bit(7)
      }
      when(io.address === 0x305.U(12)) { mtvec := (writeData.asBits.bits(31, 2) ## 0.B(2)).asUInt }
      when(io.address === 0x340.U(12)) { mscratch := writeData }
      when(io.address === 0x341.U(12)) { mepc := (writeData.asBits.bits(31, 2) ## 0.B(2)).asUInt }
      when(io.address === 0x342.U(12)) { mcause := writeData }
      when(io.address === 0x343.U(12)) { mtval := writeData }
    }
    when(io.mret & !io.trap) {
      mie := mpie
      mpie := true.B
    }
    when(io.trap) {
      mie := false.B
      mpie := mie
      mepc := (io.trapPc.asBits.bits(31, 2) ## 0.B(2)).asUInt
      mcause := io.cause
      mtval := io.tval
    }
