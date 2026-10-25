// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

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
    io.instruction.request.ready := !active & !selectData
    io.data.request.ready := !active & selectData
    val accepted = (io.instruction.request.valid & io.instruction.request.ready) |
      (io.data.request.valid & io.data.request.ready)
    when(accepted) {
      active := true.B
      done := false.B
      dataOwner := selectData
      preferData := !selectData
      awSent := false.B
      wSent := false.B
      arSent := false.B
      request :<= io.instruction.request.bits
      when(selectData) { request :<= io.data.request.bits }
    }

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
    when(io.axi.aw.valid & io.axi.aw.ready) { awSent := true.B }
    when(io.axi.w.valid & io.axi.w.ready) { wSent := true.B }
    when(io.axi.ar.valid & io.axi.ar.ready) { arSent := true.B }
    when(io.axi.b.valid & io.axi.b.ready) {
      result.data := 0.U(32)
      result.fault := io.axi.b.bits.response =/= 0.U(2)
      done := true.B
    }
    when(io.axi.r.valid & io.axi.r.ready) {
      result.data := io.axi.r.bits.data
      result.fault := io.axi.r.bits.response =/= 0.U(2)
      done := true.B
    }

    io.instruction.response.valid := active & done & !dataOwner
    io.data.response.valid := active & done & dataOwner
    io.instruction.response.bits :<= result
    io.data.response.bits :<= result
    when(active & done & dataOwner.?(io.data.response.ready, io.instruction.response.ready)) {
      active := false.B
      done := false.B
    }
