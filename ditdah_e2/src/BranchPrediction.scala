// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class BranchPredictionIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val fetchPc = Flipped(UInt(32))
  val fetchMachine = Flipped(Bool())
  val fetchFault = Flipped(Bool())
  val fetchAccepted = Flipped(Bool())
  val learn = Flipped(Bool())
  val learnPc = Flipped(UInt(32))
  val learnTarget = Flipped(UInt(32))
  val learnMachine = Flipped(Bool())
  val executeAccepted = Flipped(Bool())
  val executeNextPc = Flipped(UInt(32))
  val clear = Flipped(Bool())
  val predict = Aligned(Bool())
  val target = Aligned(UInt(32))
  val executePredicted = Aligned(Bool())
  val correction = Aligned(Bool())

@generator
object BranchPrediction extends Generator[Parameters, UnitLayers, BranchPredictionIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2BranchPrediction"
  def architecture(p: Parameters) =
    val io = summon[Interface[BranchPredictionIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val valid = RegInit(false.B)
    val sourcePc = Reg(UInt(32))
    val targetPc = Reg(UInt(32))
    val machine = Reg(Bool())
    val predicted = RegInit(false.B)
    val replaced = RegInit(false.B)
    val hit = valid & (sourcePc === io.fetchPc) & (machine === io.fetchMachine) & !io.fetchFault
    val replacement = io.learn & (io.learnTarget =/= targetPc)
    // A replaced entry may conservatively redirect even if its old target was correct.
    val correction = predicted & (replaced | (targetPc =/= io.executeNextPc))
    io.predict := hit
    io.target := targetPc
    io.executePredicted := predicted
    io.correction := correction
    when(predicted & replacement) { replaced := true.B }
    when(io.executeAccepted) { predicted := false.B; replaced := false.B }
    when(io.fetchAccepted) {
      predicted := hit
      replaced := hit & replacement
    }
    when(io.executeAccepted & correction & !io.learn) { valid := false.B }
    when(io.learn) {
      valid := true.B
      sourcePc := io.learnPc
      targetPc := io.learnTarget
      machine := io.learnMachine
    }
    when(io.clear) { valid := false.B; predicted := false.B; replaced := false.B }
