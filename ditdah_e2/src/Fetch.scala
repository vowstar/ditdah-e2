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
    val assemblyPc = RegInit(BigInt(p.resetVector).U(32))
    val nextWord = RegInit(BigInt(p.resetVector & 0xfffffffcL).U(32))
    val outstanding = RegInit(false.B)
    val discarded = RegInit(false.B)
    val address = Reg(UInt(32))
    val held = RegInit(false.B)
    val heldAddress = Reg(UInt(32))
    val heldMachine = Reg(Bool())
    val heldDiscarded = RegInit(false.B)
    val firstValid = RegInit(false.B)
    val secondValid = RegInit(false.B)
    val firstWord = Reg(UInt(32))
    val secondWord = Reg(UInt(32))
    val firstAddress = Reg(UInt(32))
    val secondAddress = Reg(UInt(32))
    val firstFault = Reg(Bool())
    val secondFault = Reg(Bool())
    val buffered = RegInit(false.B)
    val packet = Reg(new Instruction)
    val flush = io.redirect | io.pause
    io.output.valid := buffered & !flush
    io.output.bits :<= packet
    val consume = io.output.valid & io.output.ready
    io.memory.response.ready := outstanding
    val response = io.memory.response.valid & io.memory.response.ready
    val append = response & !discarded & !flush
    val headValid = firstValid | append
    val tailValid = secondValid | (append & firstValid)
    val headWord = firstValid.?(firstWord, io.memory.response.bits.data)
    val tailWord = secondValid.?(secondWord, io.memory.response.bits.data)
    val headAddress = firstValid.?(firstAddress, address)
    val tailAddress = secondValid.?(secondAddress, address)
    val headFault = firstValid.?(firstFault, io.memory.response.bits.fault)
    val tailFault = secondValid.?(secondFault, io.memory.response.bits.fault)
    val upper = if p.enableC then assemblyPc.asBits.bit(1) else false.B
    val half = upper.?(headWord.asBits.bits(31, 16), headWord.asBits.bits(15, 0))
    val short = if p.enableC then half.bits(1, 0) =/= 3.B(2) else false.B
    val crossing = upper & !short
    val available = headValid & (headFault | !crossing | tailValid)
    val assemble = available & (!buffered | consume) & !flush
    val releaseFirst = if p.enableC then upper | (!short & !headFault) else true.B
    val release = assemble & releaseFirst
    val failed = headFault | (crossing & tailFault)
    val length = if p.enableC then (headFault | short).?(2.U(3), 4.U(3)) else 4.U(3)
    val raw = if p.enableC then short.?((0.B(16) ## half).asUInt,
      crossing.?((tailWord.asBits.bits(15, 0) ## half).asUInt, headWord)) else headWord
    // A completed response can supply bytes to the registered output packet.
    when(consume) { buffered := false.B }
    when(assemble) {
      buffered := true.B
      packet.pc := assemblyPc
      packet.word := (if p.enableC then failed.?(0.U(32), raw) else raw)
      packet.length := length
      packet.fault := failed
      packet.faultAddress := headFault.?(
        (headAddress + upper.?(2.U(32), 0.U(32))).asBits.bits(31, 0).asUInt,
        (crossing & tailFault).?(tailAddress, assemblyPc))
      assemblyPc := (assemblyPc + length).asBits.bits(31, 0).asUInt
    }
    when(append | assemble) {
      firstValid := release.?(tailValid, headValid)
      firstWord := release.?(tailWord, headWord)
      firstAddress := release.?(tailAddress, headAddress)
      firstFault := release.?(tailFault, headFault)
      secondValid := tailValid & !release
      secondWord := tailWord
      secondAddress := tailAddress
      secondFault := tailFault
    }
    val space = !tailValid | release
    val offer = !held & !flush & (!outstanding | response) & space
    io.memory.request.valid := held | offer
    io.memory.request.bits.address := held.?(heldAddress, nextWord)
    io.memory.request.bits.machine := held.?(heldMachine, io.machine)
    io.memory.request.bits.write := false.B
    io.memory.request.bits.data := 0.U(32)
    io.memory.request.bits.mask := 0.U(4)
    io.memory.request.bits.size := 2.U(2)
    io.memory.request.bits.operation := 0.U(4)
    val request = io.memory.request.valid & io.memory.request.ready
    io.idle := !held & !outstanding & !firstValid & !secondValid & !buffered
    when(response) { outstanding := false.B }
    when(offer) {
      nextWord := (nextWord + 4.U(32)).asBits.bits(31, 0).asUInt
      when(!io.memory.request.ready) {
        held := true.B
        heldAddress := nextWord
        heldMachine := io.machine
        heldDiscarded := false.B
      }
    }
    when(flush) {
      firstValid := false.B
      secondValid := false.B
      buffered := false.B
      when(outstanding) { discarded := true.B }
      when(held) { heldDiscarded := true.B }
    }
    // New acceptance takes ownership after the previous response completes.
    when(request) {
      outstanding := true.B
      address := io.memory.request.bits.address
      discarded := flush | (held & heldDiscarded)
      held := false.B
    }
    when(io.redirect) {
      assemblyPc := io.target
      nextWord := (io.target.asBits.bits(31, 2) ## 0.B(2)).asUInt
    }
