// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@generator
object LocalMemory extends Generator[LocalMemoryParameters, LocalMemoryLayers, LocalMemoryIO, LocalMemoryProbe]:
  override def moduleName(p: LocalMemoryParameters): String =
    s"DitDahE2LocalMemory_${p.baseAddress.toHexString}_${p.sizeBytes}_${p.readLatency}"
  def architecture(p: LocalMemoryParameters) =
    val io = summon[Interface[LocalMemoryIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val geometry = SramParameters(p.sizeBytes / 4, 32, 8, p.readLatency)
    val storage = Sram.instantiate(geometry)
    storage.io.clock := io.clock
    val active = RegInit(false.B)
    val dataOwner = RegInit(false.B)
    val preferData = RegInit(false.B)
    val fault = RegInit(false.B)
    val write = RegInit(false.B)
    val waiting = RegInit(false.B)
    val responseValid = active & !waiting
    val responseReady = dataOwner.?(io.data.response.ready, io.instruction.response.ready)
    val completed = responseValid & responseReady
    val capacity = !active | completed
    val selectData = io.data.request.valid & (!io.instruction.request.valid | preferData)
    io.instruction.request.ready := capacity & !selectData
    io.data.request.ready := capacity & selectData
    val accepted = capacity & (io.instruction.request.valid | io.data.request.valid)
    val request = Wire(new MemoryRequest)
    request :<= io.instruction.request.bits
    when(selectData) { request :<= io.data.request.bits }
    val wide = (0.B(1) ## request.address.asBits).asUInt
    val inRange = (wide >= BigInt(p.baseAddress).U(33)) &
      (wide < BigInt(p.baseAddress + p.sizeBytes).U(33))
    val lane = request.address.asBits.bits(1, 0).asUInt
    val byte = request.size === 0.U(2)
    val half = request.size === 1.U(2)
    val word = request.size === 2.U(2)
    val aligned = byte | (half & !request.address.asBits.bit(0)) | (word & (lane === 0.U(2)))
    val mask = (byte.?(1.U(4), half.?(3.U(4), 15.U(4))) << lane).asBits.bits(3, 0).asUInt
    val operation = selectData.?(io.data.request.bits.operation, io.instruction.request.bits.operation)
    val shape = aligned & (request.mask === request.write.?(mask, 0.U(4))) & (operation === 0.U(4))
    val fetchShape = !request.write & word & (lane === 0.U(2))
    val allowed = inRange & shape & (selectData | fetchShape)
    val offset = (request.address - BigInt(p.baseAddress).U(32)).asBits
    storage.io.address := offset.bits(geometry.addressWidth + 1, 2).asUInt
    storage.io.readEnable := accepted & allowed & !request.write
    storage.io.writeMask := (accepted & allowed & request.write).?(request.mask, 0.U(4))
    storage.io.writeData := request.data
    io.instruction.response.valid := responseValid & !dataOwner
    io.data.response.valid := responseValid & dataOwner
    io.instruction.response.bits.data := (fault | write).?(0.U(32), storage.io.readData)
    io.instruction.response.bits.fault := fault
    io.data.response.bits :<= io.instruction.response.bits
    when(waiting) { waiting := false.B }
    when(completed) { active := false.B }
    when(accepted) {
      active := true.B
      dataOwner := selectData
      preferData := !selectData
      fault := !allowed
      write := request.write
      waiting := (if p.readLatency == 2 then allowed & !request.write else false.B)
    }
