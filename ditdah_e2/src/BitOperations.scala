// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@generator
object BitOperations extends Generator[BitParameters, BitLayers, BitIO, BitProbe]:
  override def moduleName(p: BitParameters): String = "DitDahE2BitOperations"
  def architecture(p: BitParameters) =
    val io = summon[Interface[BitIO]]
    val word = io.word.asBits
    val a = io.a
    val b = io.b
    val opcode = word.bits(6, 0)
    val function = word.bits(14, 12)
    val upper = word.bits(31, 25)
    val immediate = opcode === 0x13.B(7)
    val shift = immediate.?(word.bits(24, 20).asUInt, b.asBits.bits(4, 0).asUInt)

    def register(code: Int, functionCode: Int) =
      (opcode === 0x33.B(7)) & (upper === code.B(7)) & (function === functionCode.B(3))

    def constant(code: Int, functionCode: Int) =
      immediate & (word.bits(31, 20) === code.B(12)) & (function === functionCode.B(3))

    def select(condition: Referable[Bool], value: Referable[UInt], binary: Boolean = false): Unit =
      when(condition) {
        io.valid := true.B
        io.result := value
        io.usesRs2 := (if binary then true.B else false.B)
      }

    io.valid := false.B
    io.result := 0.U(32)
    io.usesRs2 := false.B

    if p.enableZba then
      for amount <- 1 to 3 do
        select(register(0x10, amount * 2),
          ((a << amount.U(2)) + b).asBits.bits(31, 0).asUInt, true)

    if p.enableZbb then
      def leadingZeros(bits: Referable[Bits], width: Int): Referable[UInt] =
        if width == 1 then bits.bit(0).?(0.U(6), 1.U(6))
        else
          val half = width / 2
          val empty = bits.bits(width - 1, half) === 0.B(half)
          val selected = empty.?(bits.bits(half - 1, 0), bits.bits(width - 1, half))
          (empty.?(half.U(6), 0.U(6)) + leadingZeros(selected, half)).asBits.bits(5, 0).asUInt

      def population(parts: Seq[Referable[UInt]]): Referable[UInt] =
        if parts.size == 1 then parts.head
        else population(parts.grouped(2).map(pair =>
          (pair(0) + pair(1)).asBits.bits(5, 0).asUInt).toSeq)

      val reversed = (0 until 32).map[Referable[Bits]](index => a.asBits.bits(index, index)).reduce(_ ## _)
      val count = population((0 until 32).map(index => a.asBits.bit(index).?(1.U(6), 0.U(6))))
      val signedLess = a.asBits.asSInt < b.asBits.asSInt
      val unsignedLess = a < b
      val opposite = (0.U(5) - shift).asBits.bits(4, 0).asUInt
      val rotation = (function === 1.B(3)).?(opposite, shift)
      val rotated = ((a.asBits ## a.asBits).asUInt >> rotation).asBits.bits(31, 0).asUInt
      val bytes = (3 to 0 by -1).map[Referable[Bits]](index =>
        (a.asBits.bits(index * 8 + 7, index * 8) =/= 0.B(8)).?(255.B(8), 0.B(8))).reduce(_ ## _)
      val reversedBytes = (0 until 4).map[Referable[Bits]](index =>
        a.asBits.bits(index * 8 + 7, index * 8)).reduce(_ ## _)

      select(register(0x20, 7), (a.asBits & ~b.asBits).asUInt, true)
      select(register(0x20, 6), (a.asBits | ~b.asBits).asUInt, true)
      select(register(0x20, 4), (~(a.asBits ^ b.asBits)).asUInt, true)
      select(constant(0x600, 1), leadingZeros(a.asBits, 32))
      select(constant(0x601, 1), leadingZeros(reversed, 32))
      select(constant(0x602, 1), count)
      select(register(0x05, 6), signedLess.?(b, a), true)
      select(register(0x05, 7), unsignedLess.?(b, a), true)
      select(register(0x05, 4), signedLess.?(a, b), true)
      select(register(0x05, 5), unsignedLess.?(a, b), true)
      select(constant(0x604, 1), (a.asBits.bit(7).?(0xffffff.B(24), 0.B(24)) ## a.asBits.bits(7, 0)).asUInt)
      select(constant(0x605, 1), (a.asBits.bit(15).?(0xffff.B(16), 0.B(16)) ## a.asBits.bits(15, 0)).asUInt)
      select(register(0x04, 4) & (word.bits(24, 20) === 0.B(5)), (0.B(16) ## a.asBits.bits(15, 0)).asUInt)
      select(register(0x30, 1) | register(0x30, 5), rotated, true)
      select(immediate & (upper === 0x30.B(7)) & (function === 5.B(3)), rotated)
      select(constant(0x287, 5), bytes.asUInt)
      select(constant(0x698, 5), reversedBytes.asUInt)

    if p.enableZbs then
      val bitMask = (1.U(32) << shift).asBits.bits(31, 0)
      for (code, functionCode) <- Seq((0x24, 1), (0x24, 5), (0x34, 1), (0x14, 1)) do
        val legal = (register(code, functionCode) |
          (immediate & (upper === code.B(7)) & (function === functionCode.B(3))))
        val value = if functionCode == 5 then (a >> shift).asBits.bits(0, 0).asUInt
          else if code == 0x24 then (a.asBits & ~bitMask).asUInt
          else if code == 0x34 then (a.asBits ^ bitMask).asUInt
          else (a.asBits | bitMask).asUInt
        when(legal) {
          io.valid := true.B
          io.result := value
          io.usesRs2 := !immediate
        }
