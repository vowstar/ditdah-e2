// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class AtomicRouterIO(p: PlatformParameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val instruction = Flipped(new MemoryPort)
  val data = Flipped(new MemoryPort)
  val dataDebug = Flipped(Bool())
  val externalInstruction = Aligned(new MemoryPort)
  val externalData = Aligned(new MemoryPort)
  val atomicInstruction = Aligned(new AtomicPort)
  val atomicData = Aligned(new AtomicPort)
  val atomicDebug = Aligned(new AtomicPort)

@generator
object AtomicRouter extends Generator[PlatformParameters, PlatformLayers, AtomicRouterIO, PlatformProbe]:
  override def moduleName(p: PlatformParameters): String = "DitDahE2AtomicRouter"
  def architecture(p: PlatformParameters) =
    val io = summon[Interface[AtomicRouterIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)

    def inside(address: Referable[UInt]) =
      val wide = (0.B(1) ## address.asBits).asUInt
      (wide >= BigInt(p.ramBase).U(33)) & (wide < BigInt(p.ramBase + p.ramSize).U(33))

    def copyRequest(to: Referable[AtomicRequest], from: Referable[MemoryRequest]) =
      to.address := from.address
      to.machine := from.machine
      to.write := from.write
      to.data := from.data
      to.mask := from.mask
      to.size := from.size
      to.selectDynamic("operation") := from.selectDynamic("operation")

    val instructionActive = RegInit(false.B)
    val instructionTarget = Reg(UInt(2))
    val instructionRam = inside(io.instruction.request.bits.address)
    val instructionAllowed = io.instruction.request.bits.operation === 0.U(4)
    val instructionChoice = instructionAllowed.?(instructionRam.?(2.U(2), 1.U(2)), 0.U(2))
    io.externalInstruction.request.valid := !instructionActive & io.instruction.request.valid &
      (instructionChoice === 1.U(2))
    io.externalInstruction.request.bits :<= io.instruction.request.bits
    io.atomicInstruction.request.valid := !instructionActive & io.instruction.request.valid &
      (instructionChoice === 2.U(2))
    copyRequest(io.atomicInstruction.request.bits, io.instruction.request.bits)
    io.instruction.request.ready := !instructionActive &
      (instructionChoice === 0.U(2)).?(true.B,
        (instructionChoice === 1.U(2)).?(io.externalInstruction.request.ready, io.atomicInstruction.request.ready))
    io.instruction.response.valid := instructionActive
    io.instruction.response.bits.data := 0.U(32)
    io.instruction.response.bits.fault := true.B
    when(instructionTarget === 1.U(2)) {
      io.instruction.response.valid := instructionActive & io.externalInstruction.response.valid
      io.instruction.response.bits :<= io.externalInstruction.response.bits
    }
    when(instructionTarget === 2.U(2)) {
      io.instruction.response.valid := instructionActive & io.atomicInstruction.response.valid
      io.instruction.response.bits :<= io.atomicInstruction.response.bits
    }
    io.externalInstruction.response.ready := instructionActive & (instructionTarget === 1.U(2)) & io.instruction.response.ready
    io.atomicInstruction.response.ready := instructionActive & (instructionTarget === 2.U(2)) & io.instruction.response.ready
    when(io.instruction.request.valid & io.instruction.request.ready) {
      instructionActive := true.B
      instructionTarget := instructionChoice
    }
    when(io.instruction.response.valid & io.instruction.response.ready) { instructionActive := false.B }

    val dataActive = RegInit(false.B)
    val dataTarget = Reg(UInt(2))
    val dataRam = inside(io.data.request.bits.address)
    val ordinary = io.data.request.bits.operation === 0.U(4)
    val dataChoice = dataRam.?(io.dataDebug.?(3.U(2), 2.U(2)), ordinary.?(1.U(2), 0.U(2)))
    io.externalData.request.valid := !dataActive & io.data.request.valid & (dataChoice === 1.U(2))
    io.externalData.request.bits :<= io.data.request.bits
    io.atomicData.request.valid := !dataActive & io.data.request.valid & (dataChoice === 2.U(2))
    io.atomicDebug.request.valid := !dataActive & io.data.request.valid & (dataChoice === 3.U(2))
    copyRequest(io.atomicData.request.bits, io.data.request.bits)
    copyRequest(io.atomicDebug.request.bits, io.data.request.bits)
    val dataReady = Wire(Bool())
    dataReady := true.B
    when(dataChoice === 1.U(2)) { dataReady := io.externalData.request.ready }
    when(dataChoice === 2.U(2)) { dataReady := io.atomicData.request.ready }
    when(dataChoice === 3.U(2)) { dataReady := io.atomicDebug.request.ready }
    io.data.request.ready := !dataActive & dataReady
    io.data.response.valid := dataActive
    io.data.response.bits.data := 0.U(32)
    io.data.response.bits.fault := true.B
    when(dataTarget === 1.U(2)) {
      io.data.response.valid := dataActive & io.externalData.response.valid
      io.data.response.bits :<= io.externalData.response.bits
    }
    when(dataTarget === 2.U(2)) {
      io.data.response.valid := dataActive & io.atomicData.response.valid
      io.data.response.bits :<= io.atomicData.response.bits
    }
    when(dataTarget === 3.U(2)) {
      io.data.response.valid := dataActive & io.atomicDebug.response.valid
      io.data.response.bits :<= io.atomicDebug.response.bits
    }
    io.externalData.response.ready := dataActive & (dataTarget === 1.U(2)) & io.data.response.ready
    io.atomicData.response.ready := dataActive & (dataTarget === 2.U(2)) & io.data.response.ready
    io.atomicDebug.response.ready := dataActive & (dataTarget === 3.U(2)) & io.data.response.ready
    when(io.data.request.valid & io.data.request.ready) {
      dataActive := true.B
      dataTarget := dataChoice
    }
    when(io.data.response.valid & io.data.response.ready) { dataActive := false.B }
