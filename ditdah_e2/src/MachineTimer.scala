// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class MachineTimerIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val tick = Flipped(Bool())
  val memory = Flipped(new MemoryPort)
  val timeValue = Aligned(UInt(64))
  val timerInterrupt = Aligned(Bool())
  val softwareInterrupt = Aligned(Bool())

@generator
object MachineTimer extends Generator[Parameters, UnitLayers, MachineTimerIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2MachineTimer"
  def architecture(p: Parameters) =
    val io = summon[Interface[MachineTimerIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val time = RegInit(0.U(64))
    val compare = RegInit(BigInt("ffffffffffffffff", 16).U(64))
    val software = RegInit(false.B)
    val pending = RegInit(false.B)
    val response = Reg(new MemoryResponse)
    val request = io.memory.request.bits
    val address = request.address
    val timeLow = address === 0.U(32)
    val timeHigh = address === 4.U(32)
    val compareLow = address === 8.U(32)
    val compareHigh = address === 12.U(32)
    val softwareAddress = address === 16.U(32)
    val known = timeLow | timeHigh | compareLow | compareHigh | softwareAddress
    val valid = known & (request.size === 2.U(2)) &
      (request.mask === request.write.?(15.U(4), 0.U(4)))
    io.memory.request.ready := !pending
    io.memory.response.valid := pending
    io.memory.response.bits :<= response
    io.timeValue := time
    io.timerInterrupt := time >= compare
    io.softwareInterrupt := software
    val readData = Wire(UInt(32))
    readData := 0.U(32)
    when(timeLow) { readData := time.asBits.bits(31, 0).asUInt }
    when(timeHigh) { readData := time.asBits.bits(63, 32).asUInt }
    when(compareLow) { readData := compare.asBits.bits(31, 0).asUInt }
    when(compareHigh) { readData := compare.asBits.bits(63, 32).asUInt }
    when(softwareAddress) { readData := software.asBits.asUInt }
    when(io.tick) { time := (time + 1.U(64)).asBits.bits(63, 0).asUInt }
    when(io.memory.response.valid & io.memory.response.ready) { pending := false.B }
    when(io.memory.request.valid & io.memory.request.ready) {
      pending := true.B
      response.fault := !valid
      response.data := (valid & !request.write).?(readData, 0.U(32))
      when(valid & request.write) {
        // A time write replaces one half and suppresses the concurrent tick.
        when(timeLow) { time := (time.asBits.bits(63, 32) ## request.data.asBits).asUInt }
        when(timeHigh) { time := (request.data.asBits ## time.asBits.bits(31, 0)).asUInt }
        when(compareLow) { compare := (compare.asBits.bits(63, 32) ## request.data.asBits).asUInt }
        when(compareHigh) { compare := (request.data.asBits ## compare.asBits.bits(31, 0)).asUInt }
        when(softwareAddress) { software := request.data.asBits.bit(0) }
      }
    }
