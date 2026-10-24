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
    if p.enableC then
      val assemblyPc = RegInit(BigInt(p.resetVector).U(32))
      val nextWord = RegInit(BigInt(p.resetVector & 0xfffffffcL).U(32))
      val active = RegInit(false.B)
      val sent = RegInit(false.B)
      val discarded = RegInit(false.B)
      val address = RegInit(BigInt(p.resetVector & 0xfffffffcL).U(32))
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
      val upper = assemblyPc.asBits.bit(1)
      val half = upper.?(firstWord.asBits.bits(31, 16), firstWord.asBits.bits(15, 0))
      val short = half.bits(1, 0) =/= 3.B(2)
      val crossing = upper & !short
      val available = firstValid & (firstFault | !crossing | secondValid)
      val assemble = available & (!buffered | consume) & !flush
      val releaseFirst = upper | (!short & !firstFault)
      val failed = firstFault | (crossing & secondFault)
      val length = (firstFault | short).?(2.U(3), 4.U(3))
      val raw = short.?((0.B(16) ## half).asUInt,
        crossing.?((secondWord.asBits.bits(15, 0) ## half).asUInt, firstWord))
      io.idle := !active & !firstValid & !secondValid & !buffered
      io.memory.request.valid := active & !sent
      io.memory.request.bits.address := address
      io.memory.request.bits.write := false.B
      io.memory.request.bits.data := 0.U(32)
      io.memory.request.bits.mask := 0.U(4)
      io.memory.request.bits.size := 2.U(2)
      io.memory.response.ready := active & sent
      when(consume) { buffered := false.B }
      when(assemble) {
        buffered := true.B
        packet.pc := assemblyPc
        packet.word := failed.?(0.U(32), raw)
        packet.length := length
        packet.fault := failed
        packet.faultAddress := firstFault.?(
          (firstAddress + upper.?(2.U(32), 0.U(32))).asBits.bits(31, 0).asUInt,
          (crossing & secondFault).?(secondAddress, assemblyPc))
        assemblyPc := (assemblyPc + length).asBits.bits(31, 0).asUInt
        when(releaseFirst) {
          firstValid := secondValid
          firstWord := secondWord
          firstAddress := secondAddress
          firstFault := secondFault
          secondValid := false.B
        }
      }
      // Reserve a word slot before offering a request.
      when(!active & (!secondValid | (assemble & releaseFirst)) & !flush) {
        active := true.B
        sent := false.B
        discarded := false.B
        address := nextWord
        nextWord := (nextWord + 4.U(32)).asBits.bits(31, 0).asUInt
      }
      when(io.memory.request.valid & io.memory.request.ready) { sent := true.B }
      when(io.memory.response.valid & io.memory.response.ready) {
        active := false.B
        when(!discarded & !flush) {
          when(!firstValid | (assemble & releaseFirst & !secondValid)) {
            firstValid := true.B
            firstWord := io.memory.response.bits.data
            firstAddress := address
            firstFault := io.memory.response.bits.fault
          }.otherwise {
            secondValid := true.B
            secondWord := io.memory.response.bits.data
            secondAddress := address
            secondFault := io.memory.response.bits.fault
          }
        }
      }
      when(flush) {
        firstValid := false.B
        secondValid := false.B
        buffered := false.B
        when(active) { discarded := true.B }
      }
      when(io.redirect) {
        assemblyPc := io.target
        nextWord := (io.target.asBits.bits(31, 2) ## 0.B(2)).asUInt
      }
    else
      val nextPc = RegInit(BigInt(p.resetVector).U(32))
      val active = RegInit(false.B)
      val sent = RegInit(false.B)
      val discarded = RegInit(false.B)
      val address = RegInit(BigInt(p.resetVector).U(32))
      val buffered = RegInit(false.B)
      val packet = Reg(new Instruction)
      val flush = io.redirect | io.pause
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
          packet.length := 4.U(3)
          packet.fault := io.memory.response.bits.fault
          packet.faultAddress := address
        }
      }
      // Redirects discard responses without withdrawing offered requests.
      when(flush) {
        buffered := false.B
        when(active) { discarded := true.B }
      }
      when(io.redirect) { nextPc := io.target }
