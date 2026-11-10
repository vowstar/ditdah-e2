// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
import java.lang.foreign.Arena
import org.llvm.mlir.scalalib.capi.ir.{Block, Context}

class JtagPort extends Bundle:
  val tck = Flipped(Clock())
  val trstN = Flipped(Bool())
  val tms = Flipped(Bool())
  val tdi = Flipped(Bool())
  val tdo = Aligned(Bool())
  val tdoEnable = Aligned(Bool())

class DitDahE2JtagDtmIO(p: Parameters) extends HWBundle(p):
  val tck = Flipped(Clock())
  val reset = Flipped(Reset())
  val trstN = Flipped(Bool())
  val tms = Flipped(Bool())
  val tdi = Flipped(Bool())
  val tdo = Aligned(Bool())
  val tdoEnable = Aligned(Bool())
  val dmi = Aligned(new DmiPort)

class DitDahE2DmiBridgeIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val tck = Flipped(Clock())
  val reset = Flipped(Reset())
  val upstream = Flipped(new DmiPort)
  val downstream = Aligned(new DmiPort)

private[ditdah_e2] object DebugReset:
  class Signal extends Bundle:
    val value = Aligned(Reset())
  def release(clock: Ref[Clock], reset: Ref[Reset])(using Arena, Context, Block, InstanceContext) =
    given ClockScope = ClockScope.posedge(clock)
    given ResetScope = ResetScope.asyncActiveHigh(reset)
    val meta = RegInit(true.B)
    val held = RegInit(true.B)
    meta := false.B
    held := meta
    val released = Wire(new Signal)
    released.value := held.asReset
    released.value
