// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@generator
object DebugHart extends Generator[DebugHartParameters, DebugHartLayers, DebugHartIO, DebugHartProbe]:
  override def moduleName(p: DebugHartParameters): String = "DitDahE2DebugHart"
  def architecture(p: DebugHartParameters) =
    val io = summon[Interface[DebugHartIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val halted = RegInit(false.B)
    val stopping = RegInit(false.B)
    val stopCause = RegInit(0.U(3))
    val breakPc = Reg(UInt(32))
    val step = RegInit(false.B)
    val stepping = RegInit(false.B)
    val ebreakMachine = RegInit(false.B)
    val ebreakUser = RegInit(false.B)
    val user = RegInit(false.B)
    val cause = RegInit(0.U(3))
    val dpc = RegInit(BigInt(p.resetVector).U(32))
    val resetPending = RegInit(false.B)
    val resetting = RegInit(false.B)
    val resetEvent = RegInit(false.B)
    val resumeAck = RegInit(false.B)
    val responding = RegInit(false.B)
    val response = Reg(new DebugHartResponse)
    val owner = RegInit(false.B)
    val sending = RegInit(false.B)
    val offered = RegInit(false.B)
    val waiting = RegInit(false.B)
    val memory = Reg(new MemoryRequest)
    val control = io.debug.control
    val request = io.debug.request.bits
    val resetRequest = control.active & control.reset
    val resetBusy = resetPending | resetting | resetRequest
    val haltRequest = control.active & control.halt
    val stepComplete = stepping & io.core.completed
    val haltNeeded = stopping | haltRequest | io.core.breakpoint | stepComplete
    val entryCause = Wire(UInt(3))
    entryCause := stopCause
    when(stepComplete & !stopping) { entryCause := 4.U(3) }
    when(io.core.breakpoint & (!stopping | (stopCause === 4.U(3)))) { entryCause := 1.U(3) }
    when(haltRequest) { entryCause := 3.U(3) }
    io.core.stop := halted | haltNeeded | resetBusy
    io.core.singleStep := stepping
    io.core.ebreakMachine := ebreakMachine
    io.core.ebreakUser := (if p.protectedMode then ebreakUser else false.B)
    io.core.freezeCounters := halted | io.core.breakpoint | (stopping & (stopCause === 1.U(3)))
    io.core.coreReset := resetting
    val resume = control.active & control.resume & halted & !haltRequest & !resetBusy & !responding & !sending & !waiting
    io.core.resume := resume
    io.core.resumePc := dpc
    io.core.resumeUser := (if p.protectedMode then user else false.B)
    io.debug.status.halted := halted & !resetBusy
    io.debug.status.running := !halted & !resetBusy
    io.debug.status.unavailable := resetBusy
    io.debug.status.resetEvent := resetEvent
    io.debug.status.resumeAck := resumeAck
    io.debug.status.resetPending := resetBusy
    resetEvent := false.B
    resumeAck := false.B
    when(!halted & haltNeeded & !resetBusy) {
      stopping := true.B
      stopCause := entryCause
      when(io.core.breakpoint) { breakPc := io.core.breakpointPc }
      when(io.core.empty & io.core.fetchIdle) {
        halted := true.B
        stopping := false.B
        stepping := false.B
        cause := entryCause
        user := (if p.protectedMode then io.core.userMode else false.B)
        dpc := (entryCause === 1.U(3)).?(io.core.breakpoint.?(io.core.breakpointPc, breakPc), io.core.architecturalPc)
      }
    }
    when(resume) {
      halted := false.B
      stopping := false.B
      stepping := step
      resumeAck := true.B
    }

    val csr = request.register === 0x7b0.U(16)
    val pc = request.register === 0x7b1.U(16)
    val local = csr | pc
    val word = request.size === 2.U(2)
    val aligned = (request.size === 0.U(2)) |
      ((request.size === 1.U(2)) & !request.address.asBits.bit(0)) |
      (word & (request.address.asBits.bits(1, 0) === 0.B(2)))
    val format = request.memory.?(request.size =/= 3.U(2), word)
    io.debug.request.ready := control.active & !responding & !sending & !waiting & !resetBusy & !control.resume
    val accepted = io.debug.request.valid & io.debug.request.ready
    io.debug.response.valid := responding & control.active
    io.debug.response.bits :<= response
    io.backend.register := request.register
    io.backend.writeRequested := !request.memory & request.write
    io.backend.writeData := request.data
    io.backend.writePulse := accepted & halted & format & !request.memory & !local & request.write & !io.backend.error
    io.protection.address := request.address
    io.protection.size := request.size
    io.protection.write := request.write
    val status = (0x4000.B(16) ## ebreakMachine.asBits ## 0.B(2) ## ebreakUser.asBits ##
      0.B(1) ## 1.B(1) ## 0.B(1) ## cause.asBits ## 0.B(1) ## 1.B(1) ## 0.B(1) ##
      step.asBits ## user.?(0.B(2), 3.B(2))).asUInt
    when(io.debug.response.valid & io.debug.response.ready) {
      responding := false.B
      owner := false.B
    }
    when(accepted) {
      owner := true.B
      responding := true.B
      response.data := 0.U(32)
      response.error := (!format).?(2.U(3), (!halted).?(4.U(3), 0.U(3)))
      when(format & halted) {
        when(!request.memory) {
          response.error := (!local & io.backend.error).?(3.U(3), 0.U(3))
          when(!request.write & (local | !io.backend.error)) {
            response.data := csr.?(status, pc.?(dpc, io.backend.readData))
          }
          when(request.write & csr) {
            step := request.data.asBits.bit(2)
            ebreakMachine := request.data.asBits.bit(15)
            ebreakUser := (if p.protectedMode then request.data.asBits.bit(12) else false.B)
            user := (if p.protectedMode then request.data.asBits.bits(1, 0) === 0.B(2) else false.B)
          }
          when(request.write & pc) {
            dpc := (if p.enableC then request.data.asBits.bits(31, 1) ## 0.B(1) else request.data.asBits.bits(31, 2) ## 0.B(2)).asUInt
          }
        }
        when(request.memory) {
          response.error := 3.U(3)
          when(aligned & io.protection.allowed) {
            responding := false.B
            sending := true.B
            offered := false.B
            memory.address := request.address
            memory.machine := io.protection.machine
            memory.write := request.write
            memory.size := request.size
            val shift = (request.address.asBits.bits(1, 0) ## 0.B(3)).asUInt
            memory.data := (request.data << shift).asBits.bits(31, 0).asUInt
            val mask = (request.size === 0.U(2)).?(1.U(4), (request.size === 1.U(2)).?(3.U(4), 15.U(4)))
            memory.mask := request.write.?((mask << request.address.asBits.bits(1, 0).asUInt).asBits.bits(3, 0).asUInt, 0.U(4))
          }
        }
      }
    }
    val newOffer = control.active & !resetBusy
    io.memory.request.valid := sending & (offered | newOffer)
    io.memory.request.bits :<= memory
    io.memory.response.ready := waiting
    when(io.memory.request.valid & !io.memory.request.ready) { offered := true.B }
    when(io.memory.request.valid & io.memory.request.ready) {
      sending := false.B
      offered := false.B
      waiting := true.B
    }
    when(sending & !offered & !newOffer) {
      sending := false.B
      when(owner & control.active) {
        responding := true.B
        response.data := 0.U(32)
        response.error := 4.U(3)
      }
    }
    when(io.memory.response.valid & io.memory.response.ready) {
      waiting := false.B
      when(owner & control.active) {
        responding := true.B
        response.error := resetBusy.?(4.U(3), io.memory.response.bits.fault.?(5.U(3), 0.U(3)))
        val shift = (memory.address.asBits.bits(1, 0) ## 0.B(3)).asUInt
        val data = (io.memory.response.bits.data >> shift).asBits
        val loaded = (memory.size === 0.U(2)).?((0.B(24) ## data.bits(7, 0)).asUInt,
          (memory.size === 1.U(2)).?((0.B(16) ## data.bits(15, 0)).asUInt, data.asUInt))
        response.data := (memory.write | resetBusy | io.memory.response.bits.fault).?(0.U(32), loaded)
      }
    }
    // An inactive DM cancels command identity, but not an offered native transfer.
    when(!control.active) { responding := false.B; owner := false.B }
    when(resetRequest) { resetPending := true.B }
    when(resetBusy & !resetting & io.core.empty & io.core.fetchIdle & !sending & !waiting) {
      resetting := true.B
      halted := false.B
      stopping := false.B
      stepping := false.B
      step := false.B
      ebreakMachine := false.B
      ebreakUser := false.B
      user := false.B
      cause := 0.U(3)
      dpc := BigInt(p.resetVector).U(32)
    }
    when(resetting & !resetRequest) {
      resetting := false.B
      resetPending := false.B
      resetEvent := true.B
      halted := haltRequest | (control.active & control.haltOnReset)
      when(control.active & control.haltOnReset) { cause := 5.U(3) }
      when(haltRequest & !control.haltOnReset) { cause := 3.U(3) }
    }
