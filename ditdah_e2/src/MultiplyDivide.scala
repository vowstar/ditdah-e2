// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class MultiplyDivideRequest extends Bundle:
  val operation = Aligned(UInt(3))
  val left = Aligned(UInt(32))
  val right = Aligned(UInt(32))

class MultiplyDivideIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val cancel = Flipped(Bool())
  val request = Flipped(new Channel(new MultiplyDivideRequest))
  val response = Aligned(new Channel(UInt(32)))

@generator
object MultiplyDivide extends Generator[Parameters, UnitLayers, MultiplyDivideIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2MultiplyDivide"
  def architecture(p: Parameters) =
    val io = summon[Interface[MultiplyDivideIO]]
    given ClockScope = ClockScope.posedge(io.clock)
    given ResetScope = ResetScope.syncActiveHigh(io.reset)
    val active = RegInit(false.B)
    val valid = RegInit(false.B)
    val value = Reg(UInt(32))
    val operation = Reg(UInt(3))
    val iteration = Reg(UInt(6))
    val negative = Reg(Bool())
    val remainderNegative = Reg(Bool())
    val zeroDivisor = Reg(Bool())
    val product = Reg(UInt(64))
    val multiplicand = Reg(UInt(64))
    val multiplier = Reg(UInt(32))
    val dividend = multiplicand.asBits.bits(63, 32).asUInt
    val divisor = multiplicand.asBits.bits(31, 0).asUInt
    val quotient = multiplier
    val remainder = product.asBits.bits(32, 0).asUInt

    io.request.ready := !active & !valid & !io.cancel
    io.response.valid := valid & !io.cancel
    io.response.bits := value
    when(io.response.valid & io.response.ready) { valid := false.B }

    val requested = io.request.bits.operation
    val leftSigned = (requested === 1.U(3)) | (requested === 2.U(3)) |
      (requested === 4.U(3)) | (requested === 6.U(3))
    val rightSigned = (requested === 1.U(3)) | (requested === 4.U(3)) | (requested === 6.U(3))
    val leftNegative = leftSigned & io.request.bits.left.asBits.bit(31)
    val rightNegative = rightSigned & io.request.bits.right.asBits.bit(31)
    val leftMagnitude = leftNegative.?(
      (0.U(32) - io.request.bits.left).asBits.bits(31, 0).asUInt, io.request.bits.left)
    val rightMagnitude = rightNegative.?(
      (0.U(32) - io.request.bits.right).asBits.bits(31, 0).asUInt, io.request.bits.right)

    when(io.request.valid & io.request.ready) {
      active := true.B
      operation := requested
      iteration := 0.U(6)
      negative := leftNegative ^ rightNegative
      remainderNegative := leftNegative
      zeroDivisor := io.request.bits.right === 0.U(32)
      product := 0.U(64)
      multiplicand := requested.asBits.bit(2).?(
        (io.request.bits.left.asBits ## rightMagnitude.asBits).asUInt,
        (0.B(32) ## rightMagnitude.asBits).asUInt)
      multiplier := leftMagnitude
      val narrowMultiply = (requested === 0.U(3)) &
        (io.request.bits.left.asBits.bits(31, 9) === 0.B(23)) &
        (io.request.bits.right.asBits.bits(31, 9) === 0.B(23))
      when(narrowMultiply) {
        active := false.B
        valid := true.B
        val smallProduct = io.request.bits.left.asBits.bits(8, 0).asUInt *
          io.request.bits.right.asBits.bits(8, 0).asUInt
        value := (0.B(14) ## smallProduct.asBits).asUInt
      }
    }

    val multiplyBitsPerCycle = p.multiplyBitsPerCycle
    val multiplyNext = (0 until multiplyBitsPerCycle).foldLeft[Referable[UInt]](product) { (sum, bit) =>
      val shiftedMultiplicand = if bit == 0 then multiplicand
        else (multiplicand.asBits.bits(63 - bit, 0) ## 0.B(bit)).asUInt
      val term = multiplier.asBits.bit(bit).?(shiftedMultiplicand, 0.U(64))
      (sum + term).asBits.bits(63, 0).asUInt
    }

    val shifted = (remainder.asBits.bits(31, 0) ## quotient.asBits.bits(31, 31)).asUInt
    val extendedDivisor = (0.B(1) ## divisor.asBits).asUInt
    val subtract = shifted >= extendedDivisor
    val correctedProduct = negative.?(0.U(64) - product, product).asBits
    val correctedQuotient = negative.?(0.U(32) - quotient, quotient).asBits.bits(31, 0).asUInt
    val remainderLow = remainder.asBits.bits(31, 0).asUInt
    val correctedRemainder = remainderNegative.?(0.U(32) - remainderLow, remainderLow).asBits.bits(31, 0).asUInt

    when(active) {
      val multiplyComplete = !operation.asBits.bit(2) & (multiplier === 0.U(32))
      when((iteration =/= 32.U(6)) & !multiplyComplete) {
        val advance = operation.asBits.bit(2).?(1.U(6), multiplyBitsPerCycle.U(6))
        iteration := (iteration + advance).asBits.bits(5, 0).asUInt
        when(operation.asBits.bit(2)) {
          val nextRemainder = subtract.?((shifted - extendedDivisor).asBits.bits(32, 0).asUInt, shifted)
          product := (0.B(31) ## nextRemainder.asBits).asUInt
          multiplier := (quotient.asBits.bits(30, 0) ## subtract.asBits).asUInt
        }.otherwise {
          when(multiplier.asBits.bits(multiplyBitsPerCycle - 1, 0).asUInt =/= 0.U(multiplyBitsPerCycle)) {
            product := multiplyNext
          }
          multiplicand := (multiplicand.asBits.bits(63 - multiplyBitsPerCycle, 0) ## 0.B(multiplyBitsPerCycle)).asUInt
          multiplier := (0.B(multiplyBitsPerCycle) ## multiplier.asBits.bits(31, multiplyBitsPerCycle)).asUInt
          when((operation === 0.U(3)) &
            (multiplier.asBits.bits(31, multiplyBitsPerCycle).asUInt === 0.U(32 - multiplyBitsPerCycle))) {
            active := false.B
            valid := true.B
            value := multiplyNext.asBits.bits(31, 0).asUInt
          }
        }
      }.otherwise {
        active := false.B
        valid := true.B
        value := (operation === 0.U(3)).?(
          product.asBits.bits(31, 0).asUInt, correctedProduct.bits(63, 32).asUInt)
        when(operation.asBits.bit(2)) {
          value := operation.asBits.bit(1).?(
            zeroDivisor.?(dividend, correctedRemainder),
            zeroDivisor.?(0xffffffffL.U(32), correctedQuotient))
        }
      }
    }
    when(io.cancel) {
      active := false.B
      valid := false.B
    }
