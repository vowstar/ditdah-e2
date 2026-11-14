// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class MemoryRouterIO(p: PlatformParameters) extends HWBundle(p):
  val clock: BundleField[Clock] = Flipped(Clock())
  val reset: BundleField[Reset] = Flipped(Reset())
  val instruction: BundleField[MemoryPort] = Flipped(new MemoryPort)
  val data: BundleField[MemoryPort] = Flipped(new MemoryPort)
  val memoryInstruction: BundleField[MemoryPort] = Aligned(new MemoryPort)
  val memoryData: BundleField[MemoryPort] = Aligned(new MemoryPort)
  val console: BundleField[MemoryPort] = Aligned(new MemoryPort)
  val timer: BundleField[MemoryPort] = Aligned(new MemoryPort)
  val itcmInstruction = Option.when(p.itcm.exists(_.useSram))(Aligned(new MemoryPort))
  val itcmData = Option.when(p.itcm.exists(_.useSram))(Aligned(new MemoryPort))
  val dtcmInstruction = Option.when(p.dtcm.exists(_.useSram))(Aligned(new MemoryPort))
  val dtcmData = Option.when(p.dtcm.exists(_.useSram))(Aligned(new MemoryPort))

@generator
object MemoryRouter extends Generator[PlatformParameters, PlatformLayers, MemoryRouterIO, PlatformProbe]:
  override def moduleName(p: PlatformParameters): String = "DitDahE2MemoryRouter"
  def architecture(p: PlatformParameters) =
    val io = summon[Interface[MemoryRouterIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val instructionActive = RegInit(false.B)
    val instructionFault = RegInit(false.B)
    val instructionDestination = Reg(UInt(2))
    val dataActive = RegInit(false.B)
    val destination = Reg(UInt(3))
    val fetch = io.instruction.request.bits
    val request = io.data.request.bits

    def contains(address: Referable[UInt], base: Long, size: Long) =
      val wide = (0.B(1) ## address.asBits).asUInt
      (wide >= BigInt(base).U(33)) & (wide < BigInt(base + size).U(33))

    val fetchItcm = p.itcm.map(b => contains(fetch.address, b.baseAddress, b.sizeBytes)).getOrElse(false.B)
    val fetchDtcm = p.dtcm.map(b => contains(fetch.address, b.baseAddress, b.sizeBytes)).getOrElse(false.B)
    val localFetchItcm = if p.itcm.exists(_.useSram) then fetchItcm else false.B
    val localFetchDtcm = if p.dtcm.exists(_.useSram) then fetchDtcm else false.B
    val fetchRegion = contains(fetch.address, p.romBase, p.romSize) |
      contains(fetch.address, p.ramBase, p.ramSize) | fetchItcm | fetchDtcm
    val fetchAllowed = fetchRegion & (fetch.operation === 0.U(4)) & !fetch.write & (fetch.size === 2.U(2)) &
      (fetch.mask === 0.U(4)) & (fetch.address.asBits.bits(1, 0) === 0.B(2))
    io.instruction.response.valid := instructionActive & (instructionFault | io.memoryInstruction.response.valid)
    io.instruction.response.bits.data := instructionFault.?(0.U(32), io.memoryInstruction.response.bits.data)
    io.instruction.response.bits.fault := instructionFault | io.memoryInstruction.response.bits.fault
    io.memoryInstruction.response.ready := instructionActive & !instructionFault &
      (instructionDestination === 0.U(2)) & io.instruction.response.ready
    if p.itcm.exists(_.useSram) then
      io.itcmInstruction.get.response.ready := instructionActive & !instructionFault &
        (instructionDestination === 1.U(2)) & io.instruction.response.ready
      when((instructionDestination === 1.U(2)) & !instructionFault) {
        io.instruction.response.valid := instructionActive & io.itcmInstruction.get.response.valid
        io.instruction.response.bits :<= io.itcmInstruction.get.response.bits
      }
    if p.dtcm.exists(_.useSram) then
      io.dtcmInstruction.get.response.ready := instructionActive & !instructionFault &
        (instructionDestination === 2.U(2)) & io.instruction.response.ready
      when((instructionDestination === 2.U(2)) & !instructionFault) {
        io.instruction.response.valid := instructionActive & io.dtcmInstruction.get.response.valid
        io.instruction.response.bits :<= io.dtcmInstruction.get.response.bits
      }
    val instructionComplete = io.instruction.response.valid & io.instruction.response.ready
    val instructionCapacity = !instructionActive | instructionComplete
    val fetchReady = Wire(Bool())
    fetchReady := io.memoryInstruction.request.ready
    io.memoryInstruction.request.valid := instructionCapacity & io.instruction.request.valid & fetchAllowed &
      !localFetchItcm & !localFetchDtcm
    io.memoryInstruction.request.bits :<= fetch
    if p.itcm.exists(_.useSram) then
      io.itcmInstruction.get.request.valid := instructionCapacity & io.instruction.request.valid & fetchAllowed & localFetchItcm
      io.itcmInstruction.get.request.bits :<= fetch
      when(localFetchItcm) { fetchReady := io.itcmInstruction.get.request.ready }
    if p.dtcm.exists(_.useSram) then
      io.dtcmInstruction.get.request.valid := instructionCapacity & io.instruction.request.valid & fetchAllowed & localFetchDtcm
      io.dtcmInstruction.get.request.bits :<= fetch
      when(localFetchDtcm) { fetchReady := io.dtcmInstruction.get.request.ready }
    io.instruction.request.ready := instructionCapacity & (!fetchAllowed | fetchReady)
    when(instructionComplete) { instructionActive := false.B }
    when(io.instruction.request.valid & io.instruction.request.ready) {
      instructionActive := true.B
      instructionFault := !fetchAllowed
      instructionDestination := localFetchItcm.?(1.U(2), localFetchDtcm.?(2.U(2), 0.U(2)))
    }

    val byte = request.size === 0.U(2)
    val half = request.size === 1.U(2)
    val word = request.size === 2.U(2)
    val lane = request.address.asBits.bits(1, 0).asUInt
    val aligned = byte | (half & !request.address.asBits.bit(0)) | (word & (lane === 0.U(2)))
    val writeMask = (byte.?(1.U(4), half.?(3.U(4), 15.U(4))) << lane).asBits.bits(3, 0).asUInt
    val shape = aligned & (request.mask === request.write.?(writeMask, 0.U(4)))
    val rom = contains(request.address, p.romBase, p.romSize) & !request.write
    val ram = contains(request.address, p.ramBase, p.ramSize)
    val inItcm = p.itcm.map(b => contains(request.address, b.baseAddress, b.sizeBytes)).getOrElse(false.B)
    val inDtcm = p.dtcm.map(b => contains(request.address, b.baseAddress, b.sizeBytes)).getOrElse(false.B)
    val localItcm = if p.itcm.exists(_.useSram) then inItcm else false.B
    val localDtcm = if p.dtcm.exists(_.useSram) then inDtcm else false.B
    val ordinary = request.operation === 0.U(4)
    val atomicAllowed = if p.core.enableA then ordinary | ((request.operation <= 11.U(4)) & word) else ordinary
    val memory = shape & ((ordinary & (rom | ((inItcm | inDtcm) & !localItcm & !localDtcm))) |
      (atomicAllowed & ram))
    val itcm = shape & ordinary & localItcm
    val dtcm = shape & ordinary & localDtcm
    val console = ordinary & shape & word & contains(request.address, p.consoleBase, p.consoleSize)
    val timer = ordinary & shape & word & contains(request.address, p.timerBase, p.timerSize)
    val selected = memory.?(1.U(3), console.?(2.U(3), timer.?(3.U(3), itcm.?(4.U(3), dtcm.?(5.U(3), 0.U(3))))))
    io.data.response.valid := dataActive
    io.data.response.bits.data := 0.U(32)
    io.data.response.bits.fault := true.B
    when(destination === 1.U(3)) {
      io.data.response.valid := dataActive & io.memoryData.response.valid
      io.data.response.bits :<= io.memoryData.response.bits
    }
    when(destination === 2.U(3)) {
      io.data.response.valid := dataActive & io.console.response.valid
      io.data.response.bits :<= io.console.response.bits
    }
    when(destination === 3.U(3)) {
      io.data.response.valid := dataActive & io.timer.response.valid
      io.data.response.bits :<= io.timer.response.bits
    }
    if p.itcm.exists(_.useSram) then
      io.itcmData.get.response.ready := dataActive & (destination === 4.U(3)) & io.data.response.ready
      when(destination === 4.U(3)) {
        io.data.response.valid := dataActive & io.itcmData.get.response.valid
        io.data.response.bits :<= io.itcmData.get.response.bits
      }
    if p.dtcm.exists(_.useSram) then
      io.dtcmData.get.response.ready := dataActive & (destination === 5.U(3)) & io.data.response.ready
      when(destination === 5.U(3)) {
        io.data.response.valid := dataActive & io.dtcmData.get.response.valid
        io.data.response.bits :<= io.dtcmData.get.response.bits
      }
    io.memoryData.response.ready := dataActive & (destination === 1.U(3)) & io.data.response.ready
    io.console.response.ready := dataActive & (destination === 2.U(3)) & io.data.response.ready
    io.timer.response.ready := dataActive & (destination === 3.U(3)) & io.data.response.ready
    val dataComplete = io.data.response.valid & io.data.response.ready
    val dataCapacity = !dataActive | dataComplete
    io.memoryData.request.valid := dataCapacity & io.data.request.valid & memory
    io.console.request.valid := dataCapacity & io.data.request.valid & console
    io.timer.request.valid := dataCapacity & io.data.request.valid & timer
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
    if p.itcm.exists(_.useSram) then
      io.itcmData.get.request.valid := dataCapacity & io.data.request.valid & itcm
      io.itcmData.get.request.bits :<= request
      when(itcm) { ready := io.itcmData.get.request.ready }
    if p.dtcm.exists(_.useSram) then
      io.dtcmData.get.request.valid := dataCapacity & io.data.request.valid & dtcm
      io.dtcmData.get.request.bits :<= request
      when(dtcm) { ready := io.dtcmData.get.request.ready }
    io.data.request.ready := dataCapacity & ready
    when(dataComplete) { dataActive := false.B }
    when(io.data.request.valid & io.data.request.ready) {
      dataActive := true.B
      destination := selected
    }
