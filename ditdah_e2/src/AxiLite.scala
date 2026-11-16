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
    if p.axiConcurrent then
      val ports = Seq(io.instruction, io.data)
      val active = Seq.fill(2)(RegInit(false.B))
      val done = Seq.fill(2)(RegInit(false.B))
      val arSent = Seq.fill(2)(RegInit(false.B))
      val requests = Seq.fill(2)(Reg(new MemoryRequest))
      val results = Seq.fill(2)(Reg(new MemoryResponse))
      val firstReadData = Reg(Bool())
      val readLocked = RegInit(false.B)
      val readOwner = Reg(Bool())
      val preferReadData = RegInit(false.B)
      val writeBusy = RegInit(false.B)
      val writeOwner = Reg(Bool())
      val preferWriteData = RegInit(false.B)
      val awSent = RegInit(false.B)
      val wSent = RegInit(false.B)

      val readOutstanding = active.indices.map(i => active(i) & !done(i) & !requests(i).write & arSent(i))
      val readPending = active.indices.map(i => active(i) & !done(i) & !requests(i).write & !arSent(i))
      val selectedRead = readLocked.?(readOwner, readPending(1) & (!readPending(0) | preferReadData))
      val readRequest = Wire(new MemoryRequest)
      readRequest :<= requests(0)
      when(selectedRead) { readRequest :<= requests(1) }
      io.axi.ar.valid := readPending(0) | readPending(1)
      io.axi.ar.bits.address := (readRequest.address.asBits.bits(31, 2) ## 0.B(2)).asUInt
      io.axi.ar.bits.protection := ((!selectedRead).asBits ## 0.B(1) ## readRequest.machine.asBits).asUInt
      val returningRead = readOutstanding(1) & (!readOutstanding(0) | firstReadData)
      io.axi.r.ready := readOutstanding(0) | readOutstanding(1)
      when(io.axi.ar.valid & !io.axi.ar.ready) {
        readLocked := true.B
        readOwner := selectedRead
      }
      when(io.axi.ar.fire) {
        readLocked := false.B
        preferReadData := !selectedRead
        // Each port owns at most one read; only their issue order needs storage.
        firstReadData := ((readOutstanding(0) | readOutstanding(1)) & !io.axi.r.fire).?(
          readOutstanding(1), selectedRead)
      }

      val writePending = active.indices.map(i => active(i) & !done(i) & requests(i).write)
      val selectedWrite = writeBusy.?(writeOwner, writePending(1) & (!writePending(0) | preferWriteData))
      val writeRequest = Wire(new MemoryRequest)
      writeRequest :<= requests(0)
      when(selectedWrite) { writeRequest :<= requests(1) }
      val writeValid = writeBusy | writePending(0) | writePending(1)
      io.axi.aw.valid := writeValid & !awSent
      io.axi.aw.bits.address := (writeRequest.address.asBits.bits(31, 2) ## 0.B(2)).asUInt
      io.axi.aw.bits.protection := ((!selectedWrite).asBits ## 0.B(1) ## writeRequest.machine.asBits).asUInt
      io.axi.w.valid := writeValid & !wSent
      io.axi.w.bits.data := writeRequest.data
      io.axi.w.bits.strobe := writeRequest.mask
      io.axi.b.ready := writeBusy & awSent & wSent
      when(writeValid & !writeBusy) {
        writeBusy := true.B
        writeOwner := selectedWrite
      }
      when(io.axi.aw.fire) { awSent := true.B }
      when(io.axi.w.fire) { wSent := true.B }
      when(io.axi.b.fire) {
        writeBusy := false.B
        awSent := false.B
        wSent := false.B
        preferWriteData := !writeOwner
      }

      for i <- active.indices do
        val owner = (i == 1).B
        val readResult = io.axi.r.fire & (returningRead === owner)
        val writeResult = io.axi.b.fire & (writeOwner === owner)
        val busResult = readResult | writeResult
        val response = Wire(new MemoryResponse)
        response.data := done(i).?(results(i).data, requests(i).write.?(0.U(32), io.axi.r.bits.data))
        response.fault := done(i).?(results(i).fault,
          requests(i).write.?(io.axi.b.bits.response =/= 0.U(2), io.axi.r.bits.response =/= 0.U(2)))
        ports(i).response.valid := active(i) & (done(i) | busResult)
        ports(i).response.bits :<= response
        ports(i).request.ready := !active(i) | (ports(i).response.valid & ports(i).response.ready)
        when(io.axi.ar.fire & (selectedRead === owner)) { arSent(i) := true.B }
        when(busResult) {
          results(i).data := requests(i).write.?(0.U(32), io.axi.r.bits.data)
          results(i).fault := requests(i).write.?(io.axi.b.bits.response =/= 0.U(2), io.axi.r.bits.response =/= 0.U(2))
          done(i) := true.B
        }
        when((ports(i).response.valid & ports(i).response.ready)) {
          active(i) := false.B
          done(i) := false.B
        }
        // The completed request owns this cycle's response; replacement state starts at the edge.
        when((ports(i).request.valid & ports(i).request.ready)) {
          val unsupported = ports(i).request.bits.operation =/= 0.U(4)
          active(i) := true.B
          done(i) := unsupported
          arSent(i) := false.B
          requests(i) :<= ports(i).request.bits
          when(unsupported) {
            results(i).data := 0.U(32)
            results(i).fault := true.B
          }
        }
    else
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
