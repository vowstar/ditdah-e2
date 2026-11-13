// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@generator
object DebugSystemBus extends Generator[Parameters, UnitLayers, DebugSystemBusIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2DebugSystemBus"
  def architecture(p: Parameters) =
    val io = summon[Interface[DebugSystemBusIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val address = RegInit(0.U(32))
    val data = RegInit(0.U(32))
    val access = RegInit(2.U(3))
    val readOnAddress = RegInit(false.B)
    val readOnData = RegInit(false.B)
    val autoIncrement = RegInit(false.B)
    val error = RegInit(0.U(3))
    val busyError = RegInit(false.B)
    val pending = RegInit(false.B)
    val issued = RegInit(false.B)
    val discard = RegInit(false.B)
    val transaction = Reg(new MemoryRequest)
    val increment = Reg(Bool())
    val request = io.request
    val read = io.accepted & (request.op === 1.U(2))
    val write = io.accepted & (request.op === 2.U(2))
    val addressWrite = write & (request.address === 0x39.U(7))
    val dataRead = read & (request.address === 0x3c.U(7))
    val dataWrite = write & (request.address === 0x3c.U(7))
    val clear = (error === 0.U(3)) & !busyError

    io.idle := !pending
    io.systemBus.request.valid := pending & !issued
    io.systemBus.request.bits :<= transaction
    io.systemBus.response.ready := pending & issued
    io.readData := 0.U(32)
    when(io.active) {
      when(request.address === 0x38.U(7)) {
        io.readData := (1.B(3) ## 0.B(6) ## busyError.asBits ## pending.asBits ##
          readOnAddress.asBits ## access.asBits ## autoIncrement.asBits ## readOnData.asBits ##
          error.asBits ## 32.B(7) ## 0.B(2) ## 7.B(3)).asUInt
      }
      when(request.address === 0x39.U(7)) { io.readData := address }
      when(request.address === 0x3c.U(7)) { io.readData := data }
    }

    val start = io.active & !pending & clear &
      ((addressWrite & readOnAddress) | dataWrite | (dataRead & readOnData))
    val nextAddress = addressWrite.?(request.data, address)
    val lane = nextAddress.asBits.bits(1, 0).asUInt
    val byte = access === 0.U(3)
    val half = access === 1.U(3)
    val word = access === 2.U(3)
    val supported = byte | half | word
    val aligned = byte | (half & !nextAddress.asBits.bit(0)) | (word & (lane === 0.U(2)))
    val shift = (lane.asBits ## 0.B(3)).asUInt
    when(start) {
      when(!supported) { error := 4.U(3) }
      when(supported & !aligned) { error := 3.U(3) }
      when(supported & aligned) {
        pending := true.B
        issued := false.B
        discard := false.B
        transaction.address := nextAddress
        transaction.machine := true.B
        transaction.write := dataWrite
        transaction.data := (request.data << shift).asBits.bits(31, 0).asUInt
        transaction.mask := dataWrite.?(((byte.?(1.U(4), half.?(3.U(4), 15.U(4)))) << lane).asBits.bits(3, 0).asUInt, 0.U(4))
        transaction.size := access.asBits.bits(1, 0).asUInt
        transaction.selectDynamic("operation") := 0.U(4)
        increment := autoIncrement
      }
    }
    when(io.active & addressWrite) {
      when(pending) { busyError := true.B }
      when(!pending) { address := request.data }
    }
    when(io.active & clear & (dataRead | dataWrite)) {
      when(pending) { busyError := true.B }
      when(!pending & dataWrite) { data := request.data }
    }
    // Busy control writes are unspecified; ignore them without changing the owner.
    when(io.active & write & (request.address === 0x38.U(7)) & !pending) {
      readOnAddress := request.data.asBits.bit(20)
      access := request.data.asBits.bits(19, 17).asUInt
      autoIncrement := request.data.asBits.bit(16)
      readOnData := request.data.asBits.bit(15)
      error := (error.asBits & ~request.data.asBits.bits(14, 12)).asUInt
      busyError := busyError & !request.data.asBits.bit(22)
    }
    when(io.systemBus.request.valid & io.systemBus.request.ready) { issued := true.B }
    when(io.systemBus.response.valid & io.systemBus.response.ready) {
      pending := false.B
      issued := false.B
      discard := false.B
      when(io.active & !discard) {
        when(io.systemBus.response.bits.fault & (error === 0.U(3))) { error := 2.U(3) }
        when(!io.systemBus.response.bits.fault) {
          val offset = (transaction.address.asBits.bits(1, 0) ## 0.B(3)).asUInt
          val loaded = (io.systemBus.response.bits.data >> offset).asBits
          when(!transaction.write) {
            data := (transaction.size === 0.U(2)).?((0.B(24) ## loaded.bits(7, 0)).asUInt,
              (transaction.size === 1.U(2)).?((0.B(16) ## loaded.bits(15, 0)).asUInt, loaded.asUInt))
          }
          val amount = (transaction.size === 0.U(2)).?(1.U(32),
            (transaction.size === 1.U(2)).?(2.U(32), 4.U(32)))
          when(increment) { address := (transaction.address + amount).asBits.bits(31, 0).asUInt }
        }
      }
    }
    // Keep offered and accepted transfers alive, but invalidate their architectural result.
    when(!io.active) {
      address := 0.U(32)
      data := 0.U(32)
      access := 2.U(3)
      readOnAddress := false.B
      readOnData := false.B
      autoIncrement := false.B
      error := 0.U(3)
      busyError := false.B
      when(pending) { discard := true.B }
    }
