// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
import me.jiuyang.stdlib.*
import me.jiuyang.stdlib.default.{*, given}

@generator
object AxiLite extends Generator[Parameters, UnitLayers, AxiLiteIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2AxiLite"
  def architecture(p: Parameters) =
    val io = summon[Interface[AxiLiteIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val active = RegInit(false.B)
    val done = RegInit(false.B)
    val dataOwner = RegInit(false.B)
    val preferData = RegInit(false.B)
    val request = Reg(new MemoryRequest)
    val result = Reg(new MemoryResponse)
    val awSent = RegInit(false.B)
    val wSent = RegInit(false.B)
    val arSent = RegInit(false.B)
    val selectData = io.data.request.valid & (!io.instruction.request.valid | preferData)
    val busResponse = io.axi.b.fire | io.axi.r.fire
    val responseValid = active & (done | busResponse)
    val responseReady = dataOwner.?(io.data.response.ready, io.instruction.response.ready)
    val completed = responseValid & responseReady
    val capacity = !active | completed
    io.instruction.request.ready := capacity & !selectData
    io.data.request.ready := capacity & selectData
    val accepted = (io.instruction.request.valid & io.instruction.request.ready) |
      (io.data.request.valid & io.data.request.ready)
    val address = (request.address.asBits.bits(31, 2) ## 0.B(2)).asUInt
    val protection = ((!dataOwner).asBits ## 0.B(1) ## request.machine.asBits).asUInt
    io.axi.aw.valid := active & request.write & !awSent & !done
    io.axi.aw.bits.address := address
    io.axi.aw.bits.protection := protection
    io.axi.w.valid := active & request.write & !wSent & !done
    io.axi.w.bits.data := request.data
    io.axi.w.bits.strobe := request.mask
    io.axi.ar.valid := active & !request.write & !arSent & !done
    io.axi.ar.bits.address := address
    io.axi.ar.bits.protection := protection
    io.axi.b.ready := active & request.write & awSent & wSent & !done
    io.axi.r.ready := active & !request.write & arSent & !done
    when(io.axi.aw.fire) { awSent := true.B }
    when(io.axi.w.fire) { wSent := true.B }
    when(io.axi.ar.fire) { arSent := true.B }
    when(io.axi.b.fire) {
      result.data := 0.U(32)
      result.fault := io.axi.b.bits.response =/= 0.U(2)
      done := true.B
    }
    when(io.axi.r.fire) {
      result.data := io.axi.r.bits.data
      result.fault := io.axi.r.bits.response =/= 0.U(2)
      done := true.B
    }

    val response = Wire(new MemoryResponse)
    response.data := done.?(result.data, request.write.?(0.U(32), io.axi.r.bits.data))
    response.fault := done.?(result.fault, request.write.?(io.axi.b.bits.response =/= 0.U(2), io.axi.r.bits.response =/= 0.U(2)))
    io.instruction.response.valid := responseValid & !dataOwner
    io.data.response.valid := responseValid & dataOwner
    io.instruction.response.bits :<= response
    io.data.response.bits :<= response
    when(completed) {
      active := false.B
      done := false.B
    }
    // The old owner selects the response until this edge; the replacement wins state updates.
    when(accepted) {
      active := true.B
      val unsupported = selectData.?(io.data.request.bits.operation, io.instruction.request.bits.operation) =/= 0.U(4)
      done := unsupported
      when(unsupported) { result.data := 0.U(32); result.fault := true.B }
      dataOwner := selectData
      preferData := !selectData
      awSent := false.B
      wSent := false.B
      arSent := false.B
      request :<= io.instruction.request.bits
      when(selectData) { request :<= io.data.request.bits }
    }
