// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class MemoryProtectionIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val allowed = Flipped(Bool())
  val input = Flipped(new MemoryPort)
  val output = Aligned(new MemoryPort)

@generator
object MemoryProtection extends Generator[Parameters, UnitLayers, MemoryProtectionIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2MemoryProtection"
  def architecture(p: Parameters) =
    val io = summon[Interface[MemoryProtectionIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val active = RegInit(false.B)
    val denied = RegInit(false.B)
    val held = RegInit(false.B)
    val heldPermission = Reg(Bool())
    val permitted = held.?(heldPermission, io.allowed)
    io.input.response.valid := active & (denied | io.output.response.valid)
    io.input.response.bits.data := denied.?(0.U(32), io.output.response.bits.data)
    io.input.response.bits.fault := denied | io.output.response.bits.fault
    io.output.response.ready := active & !denied & io.input.response.ready
    val complete = io.input.response.valid & io.input.response.ready
    val available = !active | complete
    io.output.request.valid := available & io.input.request.valid & permitted
    io.output.request.bits :<= io.input.request.bits
    io.input.request.ready := available & (!permitted | io.output.request.ready)
    val accepted = io.input.request.valid & io.input.request.ready
    // Preserve the decision for every offer that crosses a clock edge.
    when(io.input.request.valid & !io.input.request.ready & !held) {
      held := true.B
      heldPermission := io.allowed
    }
    when(complete) { active := false.B }
    when(accepted) {
      active := true.B
      denied := !permitted
      held := false.B
    }
