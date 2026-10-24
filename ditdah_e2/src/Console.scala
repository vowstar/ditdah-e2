// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class ConsoleIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val memory = Flipped(new MemoryPort)
  val transmit = Aligned(new Channel(UInt(8)))

@generator
object Console extends Generator[Parameters, UnitLayers, ConsoleIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2Console"
  def architecture(p: Parameters) =
    val io = summon[Interface[ConsoleIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val sending = RegInit(false.B)
    val responding = RegInit(false.B)
    val byte = Reg(UInt(8))
    val response = Reg(new MemoryResponse)
    val request = io.memory.request.bits
    val word = request.size === 2.U(2)
    val write = word & (request.address === 0.U(32)) & request.write & (request.mask === 15.U(4))
    val status = word & (request.address === 4.U(32)) & !request.write & (request.mask === 0.U(4))
    io.memory.request.ready := !sending & !responding
    io.memory.response.valid := responding
    io.memory.response.bits :<= response
    io.transmit.valid := sending
    io.transmit.bits := byte
    when(io.memory.response.valid & io.memory.response.ready) { responding := false.B }
    when(io.memory.request.valid & io.memory.request.ready) {
      sending := write
      responding := !write
      byte := request.data.asBits.bits(7, 0).asUInt
      response.fault := !(write | status)
      response.data := status.?(io.transmit.ready.asBits.asUInt, 0.U(32))
    }
    // Complete a store only after the byte transfers.
    when(io.transmit.valid & io.transmit.ready) {
      sending := false.B
      responding := true.B
    }
