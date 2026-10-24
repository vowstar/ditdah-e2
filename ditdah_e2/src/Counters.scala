// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class CounterIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val retire = Flipped(Bool())
  val inhibit = Flipped(UInt(3))
  val writeCycle = Flipped(Bool())
  val writeInstret = Flipped(Bool())
  val high = Flipped(Bool())
  val writeData = Flipped(UInt(32))
  val cycleCount = Aligned(UInt(64))
  val instretCount = Aligned(UInt(64))

@generator
object Counters extends Generator[Parameters, UnitLayers, CounterIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2Counters"
  def architecture(p: Parameters) =
    val io = summon[Interface[CounterIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val cycleCount = RegInit(0.U(64))
    val instretCount = RegInit(0.U(64))
    when(!io.inhibit.asBits.bit(0)) {
      cycleCount := (cycleCount + 1.U(64)).asBits.bits(63, 0).asUInt
    }
    when(io.retire & !io.inhibit.asBits.bit(2)) {
      instretCount := (instretCount + 1.U(64)).asBits.bits(63, 0).asUInt
    }
    when(io.writeCycle) {
      cycleCount := io.high.?(
        (io.writeData.asBits ## cycleCount.asBits.bits(31, 0)).asUInt,
        (cycleCount.asBits.bits(63, 32) ## io.writeData.asBits).asUInt)
    }
    when(io.writeInstret) {
      instretCount := io.high.?(
        (io.writeData.asBits ## instretCount.asBits.bits(31, 0)).asUInt,
        (instretCount.asBits.bits(63, 32) ## io.writeData.asBits).asUInt)
    }
    io.cycleCount := cycleCount
    io.instretCount := instretCount
