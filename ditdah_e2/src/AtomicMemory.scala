// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@generator
object AtomicMemory extends Generator[AtomicParameters, AtomicLayers, AtomicMemoryIO, AtomicProbe]:
  override def moduleName(p: AtomicParameters): String = "DitDahE2AtomicMemory"
  def architecture(p: AtomicParameters) =
    val io = summon[Interface[AtomicMemoryIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val ports = Seq(io.instruction, io.data, io.debug, io.competitor)
    val responding = Seq.fill(4)(RegInit(false.B))
    val responses = Seq.fill(4)(Reg(new MemoryResponse))
    val next = RegInit(0.U(2))
    val busy = RegInit(false.B)
    val owner = Reg(UInt(2))
    val request = Reg(new AtomicRequest)
    val fault = Reg(Bool())
    val reserved = RegInit(false.B)
    val reservedAddress = Reg(UInt(30))
    val eligible = ports.zip(responding).map((port, valid) => port.request.valid & (!valid | port.response.ready))
    val selected = Wire(UInt(2))
    val found = eligible.reduce(_ | _)
    selected := 0.U(2)
    for start <- 0 until 4 do
      when(next === start.U(2)) {
        for offset <- (0 until 4).reverse do
          val index = (start + offset) % 4
          when(eligible(index)) { selected := index.U(2) }
      }
    val incoming = Wire(new AtomicRequest)
    incoming :<= ports.head.request.bits
    for index <- 0 until 4 do
      when(selected === index.U(2)) { incoming :<= ports(index).request.bits }
      ports(index).request.ready := !busy & found & (selected === index.U(2))
      ports(index).response.valid := responding(index)
      ports(index).response.bits :<= responses(index)
      when(ports(index).response.valid & ports(index).response.ready) { responding(index) := false.B }
    val accepted = !busy & found
    val incomingOperation = incoming.selectDynamic("operation")
    val requestedOperation = request.selectDynamic("operation")
    val lane = incoming.address.asBits.bits(1, 0).asUInt
    val byte = incoming.size === 0.U(2)
    val half = incoming.size === 1.U(2)
    val word = incoming.size === 2.U(2)
    val aligned = byte | (half & !incoming.address.asBits.bit(0)) | (word & (lane === 0.U(2)))
    val mask = (byte.?(1.U(4), half.?(3.U(4), 15.U(4))) << lane).asBits.bits(3, 0).asUInt
    val ordinary = incomingOperation === 0.U(4)
    val lr = incomingOperation === 1.U(4)
    val atomic = (incomingOperation >= 1.U(4)) & (incomingOperation <= 11.U(4))
    val shape = ordinary.?(aligned & (incoming.mask === incoming.write.?(mask, 0.U(4))),
      atomic & word & (lane === 0.U(2)) & (incoming.write === !lr) & (incoming.mask === lr.?(0.U(4), 15.U(4))))
    val portAllowed = (selected === 0.U(2)).?(ordinary & !incoming.write & word,
      (selected === 1.U(2)) | ordinary)
    val wide = (0.B(1) ## incoming.address.asBits).asUInt
    val inRange = (wide >= BigInt(p.baseAddress).U(33)) & (wide < BigInt(p.baseAddress + p.sizeBytes).U(33))
    val incomingFault = !shape | !portAllowed | !inRange
    when(accepted) {
      busy := true.B
      owner := selected
      request :<= incoming
      fault := incomingFault
      next := (selected + 1.U(2)).asBits.bits(1, 0).asUInt
    }
    val memory = AtomicSram.instantiate(p)
    memory.io.clock := io.clock
    val address = busy.?(request.address, incoming.address)
    val offset = (address - BigInt(p.baseAddress).U(32)).asBits
    memory.io.address := offset.bits(p.addressWidth + 1, 2).asUInt
    memory.io.readEnable := accepted & !incomingFault & !io.reset.asBool
    val oldValue = memory.io.readData
    val result = Wire(UInt(32))
    result := request.data
    when(requestedOperation === 4.U(4)) { result := (oldValue + request.data).asBits.bits(31, 0).asUInt }
    when(requestedOperation === 5.U(4)) { result := (oldValue.asBits ^ request.data.asBits).asUInt }
    when(requestedOperation === 6.U(4)) { result := (oldValue.asBits & request.data.asBits).asUInt }
    when(requestedOperation === 7.U(4)) { result := (oldValue.asBits | request.data.asBits).asUInt }
    val signedLess = oldValue.asBits.asSInt < request.data.asBits.asSInt
    val unsignedLess = oldValue < request.data
    when(requestedOperation === 8.U(4)) { result := signedLess.?(oldValue, request.data) }
    when(requestedOperation === 9.U(4)) { result := signedLess.?(request.data, oldValue) }
    when(requestedOperation === 10.U(4)) { result := unsignedLess.?(oldValue, request.data) }
    when(requestedOperation === 11.U(4)) { result := unsignedLess.?(request.data, oldValue) }
    val sc = requestedOperation === 2.U(4)
    val wordAddress = request.address.asBits.bits(31, 2).asUInt
    val success = reserved & (reservedAddress === wordAddress) & !io.clearReservation
    val write = busy & !fault & request.write & (!sc | success)
    memory.io.writeMask := (write & !io.reset.asBool).?(request.mask, 0.U(4))
    memory.io.writeData := result
    when(busy) {
      busy := false.B
      for index <- 0 until 4 do
        when(owner === index.U(2)) {
          responding(index) := true.B
          responses(index).fault := fault
          responses(index).data := fault.?(0.U(32), sc.?(success.?(0.U(32), 1.U(32)),
            ((requestedOperation === 0.U(4)) & request.write).?(0.U(32), oldValue)))
        }
      when((owner === 1.U(2)) & sc) { reserved := false.B }
      when(!fault & (requestedOperation === 1.U(4))) {
        reserved := true.B
        reservedAddress := wordAddress
      }
      when(write & (reservedAddress === wordAddress)) { reserved := false.B }
    }
    when(io.clearReservation) { reserved := false.B }
