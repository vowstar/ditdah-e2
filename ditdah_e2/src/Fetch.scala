// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@generator
object Fetch extends Generator[Parameters, UnitLayers, FetchIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2Fetch"
  def architecture(p: Parameters) =
    val io = summon[Interface[FetchIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val nextPc = RegInit(BigInt(p.resetVector).U(32))
    val active = RegInit(false.B)
    val sent = RegInit(false.B)
    val discarded = RegInit(false.B)
    val address = RegInit(BigInt(p.resetVector).U(32))
    val buffered = RegInit(false.B)
    val packet = Reg(new Instruction)
    val flush = io.redirect | io.halt
    io.output.valid := buffered & !flush
    io.output.bits :<= packet
    val consume = io.output.valid & io.output.ready
    io.idle := !active & !buffered
    io.memory.request.valid := active & !sent
    io.memory.request.bits.address := address
    io.memory.request.bits.write := false.B
    io.memory.request.bits.data := 0.U(32)
    io.memory.request.bits.mask := 0.U(4)
    io.memory.request.bits.size := 2.U(2)
    io.memory.response.ready := active & sent & (!buffered | consume | discarded | flush)
    when(consume) { buffered := false.B }
    when(!active & (!buffered | consume) & !flush) {
      active := true.B
      sent := false.B
      discarded := false.B
      address := nextPc
      nextPc := (nextPc + 4.U(32)).asBits.bits(31, 0).asUInt
    }
    when(io.memory.request.valid & io.memory.request.ready) { sent := true.B }
    when(io.memory.response.valid & io.memory.response.ready) {
      active := false.B
      when(!discarded & !flush) {
        buffered := true.B
        packet.pc := address
        packet.word := io.memory.response.bits.data
        packet.fault := io.memory.response.bits.fault
      }
    }
    // An offered request cannot be withdrawn; redirects poison its response.
    when(flush) {
      buffered := false.B
      when(active) { discarded := true.B }
    }
    when(io.redirect) { nextPc := io.target }
