// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class MemoryArbiterIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val first = Flipped(new MemoryPort)
  val second = Flipped(new MemoryPort)
  val firstDebug = Flipped(Bool())
  val output = Aligned(new MemoryPort)
  val outputDebug = Aligned(Bool())

@generator
object MemoryArbiter extends Generator[Parameters, UnitLayers, MemoryArbiterIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2MemoryArbiter"
  def architecture(p: Parameters) =
    val io = summon[Interface[MemoryArbiterIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val active = RegInit(false.B)
    val locked = RegInit(false.B)
    val owner = RegInit(false.B)
    val debug = RegInit(false.B)
    val preferSecond = RegInit(false.B)
    val selected = Wire(Bool())
    selected := (active | locked).?(owner,
      io.second.request.valid & (!io.first.request.valid | preferSecond))
    val valid = selected.?(io.second.request.valid, io.first.request.valid)
    io.output.request.valid := !active & valid
    io.output.request.bits :<= io.first.request.bits
    when(selected) { io.output.request.bits :<= io.second.request.bits }
    io.outputDebug := (active | locked).?(debug, selected | io.firstDebug)
    io.first.request.ready := !active & !selected & io.output.request.ready
    io.second.request.ready := !active & selected & io.output.request.ready
    io.first.response.valid := active & !owner & io.output.response.valid
    io.second.response.valid := active & owner & io.output.response.valid
    io.first.response.bits :<= io.output.response.bits
    io.second.response.bits :<= io.output.response.bits
    io.output.response.ready := active & owner.?(io.second.response.ready, io.first.response.ready)

    // Ownership begins at the first offer, before a stalled target accepts it.
    when(!active & !locked & valid) {
      owner := selected
      debug := selected | io.firstDebug
      locked := true.B
    }
    when(io.output.request.valid & io.output.request.ready) {
      active := true.B
      locked := false.B
    }
    when(io.output.response.valid & io.output.response.ready) {
      active := false.B
      preferSecond := !owner
    }
