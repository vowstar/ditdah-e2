// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@generator
object Pmp extends Generator[Parameters, UnitLayers, PmpIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2Pmp"
  def architecture(p: Parameters) =
    val io = summon[Interface[PmpIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val configs = Seq.fill(16)(RegInit(0.U(8)))
    val addresses = Seq.fill(16)(RegInit(0.U(30)))
    io.implemented := false.B
    io.readData := 0.U(32)
    for group <- 0 until 4 do
      when(io.address === (0x3a0 + group).U(12)) {
        io.implemented := true.B
        io.readData := (configs(group * 4 + 3).asBits ## configs(group * 4 + 2).asBits ##
          configs(group * 4 + 1).asBits ## configs(group * 4).asBits).asUInt
        for lane <- 0 until 4 do
          val index = group * 4 + lane
          val value = io.writeData.asBits.bits(lane * 8 + 7, lane * 8)
          when(io.commitWrite & !configs(index).asBits.bit(7)) {
            configs(index) := (value.bit(7).asBits ## 0.B(2) ## value.bits(4, 2) ##
              (value.bit(1) & value.bit(0)).asBits ## value.bit(0).asBits).asUInt
          }
      }
    for index <- 0 until 16 do
      val nextTorLock = if index == 15 then false.B else
        configs(index + 1).asBits.bit(7) & (configs(index + 1).asBits.bits(4, 3) === 1.B(2))
      when(io.address === (0x3b0 + index).U(12)) {
        io.implemented := true.B
        io.readData := (0.B(2) ## addresses(index).asBits).asUInt
        when(io.commitWrite & !configs(index).asBits.bit(7) & !nextTorLock) {
          addresses(index) := io.writeData.asBits.bits(29, 0).asUInt
        }
      }

    val ranges = (0 until 16).map { index =>
      val mode = configs(index).asBits.bits(4, 3)
      val address = addresses(index).asBits
      val maskBits = (0 until 30).map { bit =>
        if bit == 0 then true.B else (0 until bit).map(position => address.bit(position)).reduce(_ & _)
      }
      val mask = maskBits.reverse.map[Referable[Bits]](_.asBits).reduce(_ ## _)
      val napotLower = (0.B(1) ## (address & ~mask) ## 0.B(2)).asUInt
      val napotUpper = (0.B(1) ## (address | mask) ## 0.B(2)).asUInt + 4.U(33)
      val word = (0.B(1) ## address ## 0.B(2)).asUInt
      val previous = if index == 0 then 0.U(33) else
        (0.B(1) ## addresses(index - 1).asBits ## 0.B(2)).asUInt
      val lower = (mode === 1.B(2)).?(previous, (mode === 2.B(2)).?(word, napotLower))
      val upper = (mode === 1.B(2)).?(word, (mode === 2.B(2)).?(word + 4.U(33), napotUpper))
      (mode =/= 0.B(2), lower, upper)
    }
    for query <- Seq(io.instruction, io.data) do
      val begin = (0.B(1) ## query.address.asBits).asUInt
      val count = (query.size === 0.U(2)).?(1.U(33), (query.size === 1.U(2)).?(2.U(33), 4.U(33)))
      val end = begin + count
      val valid = (query.size =/= 3.U(2)) & (query.kind =/= 3.U(2)) & (end <= 0x100000000L.U(33))
      val permitted = Wire(Bool())
      permitted := query.machine
      // A partial match denies even an unlocked M access.
      for index <- (0 until 16).reverse do
        val (active, lower, upper) = ranges(index)
        val overlap = active & (lower < upper) & (begin < upper) & (end > lower)
        val complete = (begin >= lower) & (end <= upper)
        val config = configs(index).asBits
        val permission = (query.kind === 0.U(2)).?(config.bit(0),
          (query.kind === 1.U(2)).?(config.bit(1), config.bit(2)))
        when(overlap) { permitted := complete & ((query.machine & !config.bit(7)) | permission) }
      query.allowed := valid & permitted
