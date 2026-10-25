// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class MemoryRouterIO(p: PlatformParameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val instruction = Flipped(new MemoryPort)
  val data = Flipped(new MemoryPort)
  val memoryInstruction = Aligned(new MemoryPort)
  val memoryData = Aligned(new MemoryPort)
  val console = Aligned(new MemoryPort)
  val timer = Aligned(new MemoryPort)

@generator
object MemoryRouter extends Generator[PlatformParameters, PlatformLayers, MemoryRouterIO, PlatformProbe]:
  override def moduleName(p: PlatformParameters): String = "DitDahE2MemoryRouter"
  def architecture(p: PlatformParameters) =
    val io = summon[Interface[MemoryRouterIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val instructionActive = RegInit(false.B)
    val instructionFault = RegInit(false.B)
    val dataActive = RegInit(false.B)
    val destination = Reg(UInt(2))
    val fetch = io.instruction.request.bits
    val request = io.data.request.bits

    def contains(address: Referable[UInt], base: Long, size: Long) =
      val wide = (0.B(1) ## address.asBits).asUInt
      (wide >= BigInt(base).U(33)) & (wide < BigInt(base + size).U(33))

    val fetchRegion = contains(fetch.address, p.romBase, p.romSize) |
      contains(fetch.address, p.ramBase, p.ramSize)
    val fetchAllowed = fetchRegion & !fetch.write & (fetch.size === 2.U(2)) &
      (fetch.mask === 0.U(4)) & (fetch.address.asBits.bits(1, 0) === 0.B(2))
    io.memoryInstruction.request.valid := !instructionActive & io.instruction.request.valid & fetchAllowed
    io.memoryInstruction.request.bits :<= fetch
    io.instruction.request.ready := !instructionActive & (!fetchAllowed | io.memoryInstruction.request.ready)
    io.instruction.response.valid := instructionActive & (instructionFault | io.memoryInstruction.response.valid)
    io.instruction.response.bits.data := instructionFault.?(0.U(32), io.memoryInstruction.response.bits.data)
    io.instruction.response.bits.fault := instructionFault | io.memoryInstruction.response.bits.fault
    io.memoryInstruction.response.ready := instructionActive & !instructionFault & io.instruction.response.ready
    when(io.instruction.request.valid & io.instruction.request.ready) {
      instructionActive := true.B
      instructionFault := !fetchAllowed
    }
    when(io.instruction.response.valid & io.instruction.response.ready) { instructionActive := false.B }

    val byte = request.size === 0.U(2)
    val half = request.size === 1.U(2)
    val word = request.size === 2.U(2)
    val lane = request.address.asBits.bits(1, 0).asUInt
    val aligned = byte | (half & !request.address.asBits.bit(0)) |
      (word & (lane === 0.U(2)))
    val writeMask = (byte.?(1.U(4), half.?(3.U(4), 15.U(4))) << lane).asBits.bits(3, 0).asUInt
    val shape = aligned & (request.mask === request.write.?(writeMask, 0.U(4)))
    val rom = contains(request.address, p.romBase, p.romSize) & !request.write
    val ram = contains(request.address, p.ramBase, p.ramSize)
    val memory = shape & (rom | ram)
    val console = shape & word & contains(request.address, p.consoleBase, p.consoleSize)
    val timer = shape & word & contains(request.address, p.timerBase, p.timerSize)
    val selected = Wire(UInt(2))
    selected := memory.?(1.U(2), console.?(2.U(2), timer.?(3.U(2), 0.U(2))))
    io.memoryData.request.valid := !dataActive & io.data.request.valid & memory
    io.console.request.valid := !dataActive & io.data.request.valid & console
    io.timer.request.valid := !dataActive & io.data.request.valid & timer
    io.memoryData.request.bits :<= request
    io.console.request.bits :<= request
    io.timer.request.bits :<= request
    io.console.request.bits.address := (request.address - BigInt(p.consoleBase).U(32)).asBits.bits(31, 0).asUInt
    io.timer.request.bits.address := (request.address - BigInt(p.timerBase).U(32)).asBits.bits(31, 0).asUInt
    val ready = Wire(Bool())
    ready := true.B
    when(memory) { ready := io.memoryData.request.ready }
    when(console) { ready := io.console.request.ready }
    when(timer) { ready := io.timer.request.ready }
    io.data.request.ready := !dataActive & ready
    io.data.response.valid := dataActive
    io.data.response.bits.data := 0.U(32)
    io.data.response.bits.fault := true.B
    when(destination === 1.U(2)) {
      io.data.response.valid := dataActive & io.memoryData.response.valid
      io.data.response.bits :<= io.memoryData.response.bits
    }
    when(destination === 2.U(2)) {
      io.data.response.valid := dataActive & io.console.response.valid
      io.data.response.bits :<= io.console.response.bits
    }
    when(destination === 3.U(2)) {
      io.data.response.valid := dataActive & io.timer.response.valid
      io.data.response.bits :<= io.timer.response.bits
    }
    io.memoryData.response.ready := dataActive & (destination === 1.U(2)) & io.data.response.ready
    io.console.response.ready := dataActive & (destination === 2.U(2)) & io.data.response.ready
    io.timer.response.ready := dataActive & (destination === 3.U(2)) & io.data.response.ready
    when(io.data.request.valid & io.data.request.ready) {
      dataActive := true.B
      destination := selected
    }
    when(io.data.response.valid & io.data.response.ready) { dataActive := false.B }
