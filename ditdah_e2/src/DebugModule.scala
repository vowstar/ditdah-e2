// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@generator
object DebugModule extends Generator[Parameters, UnitLayers, DebugModuleIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2DebugModule"
  def architecture(p: Parameters) =
    val io = summon[Interface[DebugModuleIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val active = RegInit(false.B)
    val halt = RegInit(false.B)
    val resume = RegInit(false.B)
    val resumeAck = RegInit(false.B)
    val haltOnReset = RegInit(false.B)
    val ndmreset = RegInit(false.B)
    val haveReset = RegInit(false.B)
    val data0 = RegInit(0.U(32))
    val data1 = RegInit(0.U(32))
    val program0 = RegInit(0.U(32))
    val program1 = RegInit(0.U(32))
    val executionProgram0 = Reg(UInt(32))
    val executionProgram1 = Reg(UInt(32))
    val error = RegInit(0.U(3))
    val busy = RegInit(false.B)
    val needsHart = RegInit(false.B)
    val issued = RegInit(false.B)
    val commandValid = RegInit(false.B)
    val command = Reg(new DebugAbstractCommand)
    val operands = Reg(new DebugHartOperands)
    val auto = RegInit(0.U(18))
    val responding = RegInit(false.B)
    val response = Reg(new DmiResponse)
    val request = io.dmi.request.bits
    val accepted = io.dmi.request.valid & io.dmi.request.ready
    val read = accepted & (request.op === 1.U(2))
    val write = accepted & (request.op === 2.U(2))
    val controlWrite = write & (request.address === 0x10.U(7))
    val deactivate = controlWrite & !request.data.asBits.bit(0)
    val dataAccess = (request.address === 4.U(7)) | (request.address === 5.U(7))
    val programAccess = (request.address === 0x20.U(7)) | (request.address === 0x21.U(7))
    val autoAccess = dataAccess | programAccess
    val busyConflict = active & busy & (((read | write) & autoAccess) |
      (write & ((request.address === 0x16.U(7)) | (request.address === 0x17.U(7)) |
        (request.address === 0x18.U(7)))))
    io.dmi.request.ready := !responding
    io.dmi.response.valid := responding
    io.dmi.response.bits :<= response
    io.hart.control.active := active
    io.hart.control.halt := active & halt
    io.hart.control.resume := active & resume & !halt
    io.hart.control.reset := active & ndmreset
    io.hart.control.haltOnReset := active & haltOnReset
    io.hart.request.valid := active & busy & needsHart & !issued
    io.hart.request.bits.memory := command.memory
    io.hart.request.bits.write := command.write
    io.hart.request.bits.size := command.size
    io.hart.request.bits.register := command.register
    io.hart.request.bits.address := operands.address
    io.hart.request.bits.data := operands.data
    io.hart.request.bits.transfer := command.memory | command.transfer
    io.hart.request.bits.postExec := command.postExec
    io.hart.request.bits.program0 := executionProgram0
    io.hart.request.bits.program1 := executionProgram1
    io.hart.response.ready := true.B

    val halted = io.hart.status.halted & !io.hart.status.unavailable
    val running = io.hart.status.running & !io.hart.status.unavailable
    val readData = Wire(UInt(32))
    readData := 0.U(32)
    when(active) {
      when(request.address === 4.U(7)) { readData := busy.?(0.U(32), data0) }
      when(request.address === 5.U(7)) { readData := busy.?(0.U(32), data1) }
      when(request.address === 0x20.U(7)) { readData := busy.?(0.U(32), program0) }
      when(request.address === 0x21.U(7)) { readData := busy.?(0.U(32), program1) }
      when(request.address === 0x10.U(7)) { readData := (0.B(30) ## ndmreset.asBits ## active.asBits).asUInt }
      when(request.address === 0x11.U(7)) {
        readData := (0.B(7) ## (ndmreset | io.hart.status.resetPending).asBits ## 0.B(1) ## 1.B(1) ## 0.B(2) ##
          haveReset.asBits ## haveReset.asBits ## resumeAck.asBits ## resumeAck.asBits ## 0.B(2) ##
          io.hart.status.unavailable.asBits ## io.hart.status.unavailable.asBits ##
          running.asBits ## running.asBits ## halted.asBits ## halted.asBits ## 0xa3.B(8)).asUInt
      }
      when(request.address === 0x16.U(7)) {
        readData := (0.B(3) ## 2.B(5) ## 0.B(11) ## busy.asBits ## 0.B(1) ## error.asBits ## 2.B(8)).asUInt
      }
      when(request.address === 0x18.U(7)) { readData := (0.B(14) ## auto.asBits).asUInt }
    }

    val bits = request.data.asBits
    val registerCommand = bits.bits(31, 24) === 0.B(8)
    val memoryCommand = bits.bits(31, 24) === 2.B(8)
    val transfer = bits.bit(17)
    val size = bits.bits(22, 20).asUInt
    val registerSupported = registerCommand & !bits.bit(23) & !bits.bit(19) &
      (!transfer | (size === 2.U(3)))
    val memorySupported = memoryCommand & !bits.bit(23) & (size <= 2.U(3)) &
      (bits.bits(18, 17) === 0.B(2)) & (bits.bits(15, 0) === 0.B(16))
    val supported = registerSupported | memorySupported
    val commandWrite = write & (request.address === 0x17.U(7))
    val manualStart = active & commandWrite & !busy & (error === 0.U(3)) & supported & halted
    val autoSelected = ((request.address === 4.U(7)) & auto.asBits.bit(0)) |
      ((request.address === 5.U(7)) & auto.asBits.bit(1)) |
      ((request.address === 0x20.U(7)) & auto.asBits.bit(16)) |
      ((request.address === 0x21.U(7)) & auto.asBits.bit(17))
    val autoStart = active & (read | write) & autoAccess & autoSelected & commandValid & !busy & (error === 0.U(3))
    val sampledData0 = (write & (request.address === 4.U(7))).?(request.data, data0)
    val sampledData1 = (write & (request.address === 5.U(7))).?(request.data, data1)
    val sampledProgram0 = (write & (request.address === 0x20.U(7))).?(request.data, program0)
    val sampledProgram1 = (write & (request.address === 0x21.U(7))).?(request.data, program1)
    val commandComplete = active & busy & issued & io.hart.response.valid
    val postincrement = commandComplete & command.memory & command.postIncrement &
      (io.hart.response.bits.error === 0.U(3))
    val incrementBy = (command.size === 0.U(2)).?(1.U(32), (command.size === 1.U(2)).?(2.U(32), 4.U(32)))

    when(io.dmi.response.valid & io.dmi.response.ready) { responding := false.B }
    when(accepted) {
      responding := true.B
      response.data := (request.op === 1.U(2)).?(readData, 0.U(32))
      response.status := (request.op === 3.U(2)).?(2.U(2), 0.U(2))
    }
    when(io.hart.request.valid & io.hart.request.ready) { issued := true.B }
    when(active & busy & !needsHart) { busy := false.B }
    when(commandComplete) {
      busy := false.B
      issued := false.B
      when(error === 0.U(3)) { error := io.hart.response.bits.error }
      when(io.hart.response.bits.dataValid) { data0 := io.hart.response.bits.data }
      when(postincrement) { data1 := (operands.address + incrementBy).asBits.bits(31, 0).asUInt }
    }
    when(active & resume & io.hart.status.resumeAck) {
      resume := false.B
      resumeAck := true.B
    }
    when(controlWrite) {
      active := request.data.asBits.bit(0)
      when(active & request.data.asBits.bit(0)) {
        ndmreset := request.data.asBits.bit(1)
        when(!busy) {
          halt := request.data.asBits.bit(31)
          when(request.data.asBits.bit(31)) { resume := false.B }
          when(request.data.asBits.bit(30) & !request.data.asBits.bit(31)) {
            resumeAck := false.B
            resume := halted
          }
          when(request.data.asBits.bit(28)) { haveReset := false.B }
          when(request.data.asBits.bit(3)) { haltOnReset := true.B }
          when(request.data.asBits.bit(2)) { haltOnReset := false.B }
        }
      }
    }
    when(active & io.hart.status.resetEvent) { haveReset := true.B }
    when(active & write & !busy) {
      when(request.address === 4.U(7)) { data0 := request.data }
      when(request.address === 5.U(7)) { data1 := request.data }
      when(request.address === 0x20.U(7)) { program0 := request.data }
      when(request.address === 0x21.U(7)) { program1 := request.data }
      when(request.address === 0x16.U(7)) { error := (error.asBits & ~request.data.asBits.bits(10, 8)).asUInt }
      when(request.address === 0x18.U(7)) {
        auto := (bits.bits(17, 16) ## 0.B(14) ## bits.bits(1, 0)).asUInt
      }
      when(commandWrite & (error === 0.U(3))) {
        when(!supported) { error := 2.U(3) }
        when(supported & !halted) { error := 4.U(3) }
      }
    }
    when(manualStart) {
      busy := true.B
      issued := false.B
      commandValid := true.B
      needsHart := memoryCommand | transfer | bits.bit(18)
      command.memory := memoryCommand
      command.write := bits.bit(16)
      command.size := size.asBits.bits(1, 0).asUInt
      command.register := bits.bits(15, 0).asUInt
      command.transfer := transfer
      command.postIncrement := memoryCommand & bits.bit(19)
      command.postExec := registerCommand & bits.bit(18)
      operands.address := data1
      operands.data := data0
      executionProgram0 := program0
      executionProgram1 := program1
    }
    when(autoStart) {
      busy := true.B
      issued := false.B
      needsHart := command.memory | command.transfer | command.postExec
      operands.address := sampledData1
      operands.data := sampledData0
      executionProgram0 := sampledProgram0
      executionProgram1 := sampledProgram1
    }
    // A conflicting DMI access takes priority over a command result on this edge.
    when(busyConflict & (error === 0.U(3))) { error := 1.U(3) }
    // DMI response ownership survives dmactive deactivation.
    when(!active | deactivate) {
      halt := false.B
      resume := false.B
      resumeAck := false.B
      haltOnReset := false.B
      ndmreset := false.B
      haveReset := false.B
      data0 := 0.U(32)
      data1 := 0.U(32)
      program0 := 0.U(32)
      program1 := 0.U(32)
      error := 0.U(3)
      busy := false.B
      issued := false.B
      needsHart := false.B
      commandValid := false.B
      auto := 0.U(18)
    }
