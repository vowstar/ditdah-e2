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
    val injecting = RegInit(false.B)
    val cancelInjection = RegInit(false.B)
    val pendingIssue = RegInit(false.B)
    val slot = RegInit(0.U(3))
    val program0 = Reg(UInt(32))
    val program1 = Reg(UInt(32))
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
    io.core.entry := !halted & haltNeeded & !resetBusy & io.core.empty & io.core.fetchIdle
    io.core.injectionActive := injecting
    val resume = control.active & control.resume & halted & !haltRequest & !resetBusy & !responding &
      !sending & !waiting & !injecting & !pendingIssue & !cancelInjection
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
    val format = request.memory.?(request.size =/= 3.U(2) & !request.postExec, !request.transfer | word)
    val transferError = request.transfer & !local & io.backend.error
    io.debug.request.ready := control.active & !responding & !sending & !waiting & !injecting & !pendingIssue &
      !cancelInjection & !resetBusy & !control.resume
    val accepted = io.debug.request.valid & io.debug.request.ready
    val startProgram = accepted & halted & format & !request.memory & request.postExec & !transferError
    io.debug.response.valid := responding & control.active
    io.debug.response.bits :<= response
    io.backend.register := request.register
    io.backend.writeRequested := !request.memory & request.transfer & request.write
    io.backend.writeData := request.data
    io.backend.writePulse := accepted & halted & format & !request.memory & request.transfer & !local & request.write & !io.backend.error
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
      response.dataValid := false.B
      when(format & halted) {
        when(!request.memory) {
          response.error := transferError.?(3.U(3), 0.U(3))
          when(request.transfer & !request.write & (local | !io.backend.error)) {
            response.data := csr.?(status, pc.?(dpc, io.backend.readData))
            response.dataValid := true.B
          }
          when(request.transfer & request.write & csr) {
            step := request.data.asBits.bit(2)
            ebreakMachine := request.data.asBits.bit(15)
            ebreakUser := (if p.protectedMode then request.data.asBits.bit(12) else false.B)
            user := (if p.protectedMode then request.data.asBits.bits(1, 0) === 0.B(2) else false.B)
          }
          when(request.transfer & request.write & pc) {
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
            memory.selectDynamic("operation") := 0.U(4)
            val shift = (request.address.asBits.bits(1, 0) ## 0.B(3)).asUInt
            memory.data := (request.data << shift).asBits.bits(31, 0).asUInt
            val mask = (request.size === 0.U(2)).?(1.U(4), (request.size === 1.U(2)).?(3.U(4), 15.U(4)))
            memory.mask := request.write.?((mask << request.address.asBits.bits(1, 0).asUInt).asBits.bits(3, 0).asUInt, 0.U(4))
          }
        }
      }
    }
    when(startProgram) {
      responding := false.B
      injecting := true.B
      cancelInjection := false.B
      pendingIssue := true.B
      slot := 0.U(3)
      program0 := request.program0
      program1 := request.program1
    }

    io.core.injection.valid := pendingIssue & !cancelInjection
    io.core.injection.bits.sequence := slot
    io.core.injection.bits.word := 0x00100073.U(32)
    io.core.injection.bits.length := 4.U(3)
    io.core.injection.bits.truncated := false.B
    if p.enableC then
      val raw = Wire(UInt(16))
      raw := 0.U(16)
      when(slot === 0.U(3)) {
        raw := program0.asBits.bits(15, 0).asUInt
        io.core.injection.bits.word := program0
      }
      when(slot === 1.U(3)) {
        raw := program0.asBits.bits(31, 16).asUInt
        io.core.injection.bits.word := (program1.asBits.bits(15, 0) ## program0.asBits.bits(31, 16)).asUInt
      }
      when(slot === 2.U(3)) {
        raw := program1.asBits.bits(15, 0).asUInt
        io.core.injection.bits.word := program1
      }
      when(slot === 3.U(3)) {
        raw := program1.asBits.bits(31, 16).asUInt
        io.core.injection.bits.word := (0.B(16) ## program1.asBits.bits(31, 16)).asUInt
        io.core.injection.bits.truncated := raw.asBits.bits(1, 0) === 3.B(2)
      }
      when(slot =/= 4.U(3)) {
        io.core.injection.bits.length := (raw.asBits.bits(1, 0) === 3.B(2)).?(4.U(3), 2.U(3))
        when(raw.asBits.bits(1, 0) =/= 3.B(2)) {
          io.core.injection.bits.word := (0.B(16) ## raw.asBits).asUInt
        }
      }
    else
      when(slot === 0.U(3)) { io.core.injection.bits.word := program0 }
      when(slot === 2.U(3)) { io.core.injection.bits.word := program1 }
      when((slot === 1.U(3)) | (slot === 3.U(3))) { io.core.injection.bits.truncated := true.B }

    val finishingInjection = io.core.injectionDone.valid & injecting & (io.core.injectionDone.sequence === slot) &
      (io.core.injectionDone.fault | io.core.injectionDone.ebreak | (slot === 4.U(3)))
    when(io.core.injection.valid & io.core.injection.ready) { pendingIssue := false.B }
    when(io.core.injectionDone.valid & injecting & (io.core.injectionDone.sequence === slot)) {
      pendingIssue := false.B
      when(!cancelInjection) {
        when(io.core.injectionDone.fault | io.core.injectionDone.ebreak | (slot === 4.U(3))) {
          injecting := false.B
          when(owner & control.active) {
            responding := true.B
            response.error := io.core.injectionDone.fault.?(3.U(3), 0.U(3))
          }
        }.otherwise {
          slot := (slot + (io.core.injection.bits.length === 2.U(3)).?(1.U(3), 2.U(3))).asBits.bits(2, 0).asUInt
          pendingIssue := true.B
        }
      }
    }
    when(cancelInjection & injecting & !pendingIssue & io.core.injectedIdle) {
      injecting := false.B
      cancelInjection := false.B
      when(owner & control.active) {
        responding := true.B
        response.error := 4.U(3)
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
        response.dataValid := false.B
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
        response.dataValid := !memory.write & !resetBusy & !io.memory.response.bits.fault
      }
    }

    val localAddress = io.core.localCsr.address
    val localRead = Wire(UInt(32))
    localRead := 0.U(32)
    when(localAddress === 0x7b0.U(12)) { localRead := status }
    when(localAddress === 0x7b1.U(12)) { localRead := dpc }
    val localWrite = Wire(UInt(32))
    localWrite := io.core.localCsr.operand
    when(io.core.localCsr.operation === 2.U(2)) { localWrite := (localRead.asBits | io.core.localCsr.operand.asBits).asUInt }
    when(io.core.localCsr.operation === 3.U(2)) { localWrite := (localRead.asBits & ~io.core.localCsr.operand.asBits).asUInt }
    val dcsrMask = (if p.protectedMode then 0x9007L else 0x8004L).U(32)
    val localPrv = (if p.protectedMode then (localWrite.asBits.bits(1, 0) === 0.B(2)).?(0.B(2), 3.B(2)) else 3.B(2))
    val dcsrValue = ((status.asBits & ~dcsrMask.asBits) |
      (localWrite.asBits & dcsrMask.asBits & 0xfffffffcL.B(32)) | localPrv.asBits).asUInt
    val dpcValue = (if p.enableC then localWrite.asBits.bits(31, 1) ## 0.B(1) else localWrite.asBits.bits(31, 2) ## 0.B(2)).asUInt
    io.core.localCsr.readData := localRead
    io.core.localCsr.writeMask := 0.U(32)
    io.core.localCsr.writtenData := localRead
    when(io.core.localCsr.commit) {
      when(localAddress === 0x7b0.U(12)) {
        io.core.localCsr.writeMask := dcsrMask
        io.core.localCsr.writtenData := dcsrValue
        when(io.core.localCsr.writeRequested) {
          step := localWrite.asBits.bit(2)
          ebreakMachine := localWrite.asBits.bit(15)
          ebreakUser := (if p.protectedMode then localWrite.asBits.bit(12) else false.B)
          user := (if p.protectedMode then localWrite.asBits.bits(1, 0) === 0.B(2) else false.B)
        }
      }
      when(localAddress === 0x7b1.U(12)) {
        io.core.localCsr.writeMask := (if p.enableC then 0xfffffffeL.U(32) else 0xfffffffcL.U(32))
        io.core.localCsr.writtenData := dpcValue
        when(io.core.localCsr.writeRequested) { dpc := dpcValue }
      }
    }

    // An inactive DM cancels command identity, but not an offered native transfer.
    when(!control.active) {
      responding := false.B
      owner := false.B
    }
    when((!control.active | resetBusy) & injecting & !cancelInjection & !finishingInjection) {
      cancelInjection := true.B
    }
    when(cancelInjection) { pendingIssue := false.B }
    when(resetRequest) { resetPending := true.B }
    when(resetBusy & !resetting & io.core.empty & io.core.fetchIdle & !sending & !waiting &
      !injecting & !pendingIssue & io.core.injectedIdle) {
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
      cancelInjection := false.B
    }
    when(resetting & !resetRequest) {
      resetting := false.B
      resetPending := false.B
      resetEvent := true.B
      halted := haltRequest | (control.active & control.haltOnReset)
      when(control.active & control.haltOnReset) { cause := 5.U(3) }
      when(haltRequest & !control.haltOnReset) { cause := 3.U(3) }
    }
