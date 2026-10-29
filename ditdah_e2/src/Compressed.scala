// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class CompressedIO(p: Parameters) extends HWBundle(p):
  val raw = Flipped(UInt(16))
  val instruction = Aligned(UInt(32))
  val legal = Aligned(Bool())
  val hint = Aligned(Bool())

@generator
object Compressed extends Generator[Parameters, UnitLayers, CompressedIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2Compressed"
  def architecture(p: Parameters) =
    val io = summon[Interface[CompressedIO]]
    val bits = io.raw.asBits
    val quadrant = bits.bits(1, 0)
    val funct3 = bits.bits(15, 13)
    val rd = bits.bits(11, 7)
    val rs2 = bits.bits(6, 2)
    val prime1 = 1.B(2) ## bits.bits(9, 7)
    val prime2 = 1.B(2) ## bits.bits(4, 2)
    val sign = bits.bit(12)
    val immediate = sign.?(127.B(7), 0.B(7)) ## bits.bits(6, 2)
    val luiImmediate = sign.?(32767.B(15), 0.B(15)) ## bits.bits(6, 2)
    val stackAdd = 0.B(2) ## bits.bits(10, 7) ## bits.bits(12, 11) ## bits.bits(5, 5) ## bits.bits(6, 6) ## 0.B(2)
    val stackAdjust = sign.?(7.B(3), 0.B(3)) ## bits.bits(4, 3) ## bits.bits(5, 5) ## bits.bits(2, 2) ## bits.bits(6, 6) ## 0.B(4)
    val memoryOffset = 0.B(5) ## bits.bits(5, 5) ## bits.bits(12, 10) ## bits.bits(6, 6) ## 0.B(2)
    val stackLoad = 0.B(4) ## bits.bits(3, 2) ## bits.bits(12, 12) ## bits.bits(6, 4) ## 0.B(2)
    val stackStore = 0.B(4) ## bits.bits(8, 7) ## bits.bits(12, 9) ## 0.B(2)
    val jumpOffset = sign.?(1023.B(10), 0.B(10)) ## bits.bits(8, 8) ## bits.bits(10, 9) ##
      bits.bits(6, 6) ## bits.bits(7, 7) ## bits.bits(2, 2) ## bits.bits(11, 11) ## bits.bits(5, 3) ## 0.B(1)
    val branchOffset = sign.?(31.B(5), 0.B(5)) ## bits.bits(6, 5) ## bits.bits(2, 2) ##
      bits.bits(11, 10) ## bits.bits(4, 3) ## 0.B(1)
    val registerFunction = Wire(Bits(3))
    registerFunction := 0.B(3)
    when(bits.bits(6, 5) === 1.B(2)) { registerFunction := 4.B(3) }
    when(bits.bits(6, 5) === 2.B(2)) { registerFunction := 6.B(3) }
    when(bits.bits(6, 5) === 3.B(2)) { registerFunction := 7.B(3) }

    io.instruction := 0.U(32)
    io.legal := false.B
    io.hint := false.B
    when(quadrant === 0.B(2)) {
      when(funct3 === 0.B(3)) {
        io.legal := stackAdd =/= 0.B(12)
        io.instruction := (stackAdd ## 2.B(5) ## 0.B(3) ## prime2 ## 0x13.B(7)).asUInt
      }
      when(funct3 === 2.B(3)) {
        io.legal := true.B
        io.instruction := (memoryOffset ## prime1 ## 2.B(3) ## prime2 ## 3.B(7)).asUInt
      }
      when(funct3 === 6.B(3)) {
        io.legal := true.B
        io.instruction := (memoryOffset.bits(11, 5) ## prime2 ## prime1 ## 2.B(3) ##
          memoryOffset.bits(4, 0) ## 0x23.B(7)).asUInt
      }
    }
    when(quadrant === 1.B(2)) {
      when(funct3 === 0.B(3)) {
        io.legal := true.B
        io.hint := ((rd === 0.B(5)) | (immediate === 0.B(12))) & (io.raw =/= 1.U(16))
        io.instruction := (immediate ## rd ## 0.B(3) ## rd ## 0x13.B(7)).asUInt
      }
      when((funct3 === 1.B(3)) | (funct3 === 5.B(3))) {
        io.legal := true.B
        io.instruction := (jumpOffset.bits(20, 20) ## jumpOffset.bits(10, 1) ## jumpOffset.bits(11, 11) ##
          jumpOffset.bits(19, 12) ## (funct3 === 1.B(3)).?(1.B(5), 0.B(5)) ## 0x6f.B(7)).asUInt
      }
      when(funct3 === 2.B(3)) {
        io.legal := true.B
        io.hint := rd === 0.B(5)
        io.instruction := (immediate ## 0.B(5) ## 0.B(3) ## rd ## 0x13.B(7)).asUInt
      }
      when(funct3 === 3.B(3)) {
        io.legal := immediate =/= 0.B(12)
        io.hint := rd === 0.B(5)
        io.instruction := (luiImmediate ## rd ## 0x37.B(7)).asUInt
        when(rd === 2.B(5)) {
          io.instruction := (stackAdjust ## 2.B(5) ## 0.B(3) ## 2.B(5) ## 0x13.B(7)).asUInt
        }
      }
      when(funct3 === 4.B(3)) {
        when(bits.bits(11, 10).asUInt <= 1.U(2)) {
          io.legal := !sign
          io.hint := rs2 === 0.B(5)
          io.instruction := (0.B(1) ## bits.bits(10, 10) ## 0.B(5) ## rs2 ## prime1 ## 5.B(3) ## prime1 ## 0x13.B(7)).asUInt
        }
        when(bits.bits(11, 10) === 2.B(2)) {
          io.legal := true.B
          io.instruction := (immediate ## prime1 ## 7.B(3) ## prime1 ## 0x13.B(7)).asUInt
        }
        when(bits.bits(11, 10) === 3.B(2)) {
          io.legal := !sign
          io.instruction := ((bits.bits(6, 5) === 0.B(2)).?(32.B(7), 0.B(7)) ## prime2 ##
            prime1 ## registerFunction ## prime1 ## 0x33.B(7)).asUInt
        }
      }
      when((funct3 === 6.B(3)) | (funct3 === 7.B(3))) {
        io.legal := true.B
        io.instruction := (branchOffset.bits(12, 12) ## branchOffset.bits(10, 5) ## 0.B(5) ## prime1 ##
          0.B(2) ## bits.bits(13, 13) ## branchOffset.bits(4, 1) ## branchOffset.bits(11, 11) ## 0x63.B(7)).asUInt
      }
    }
    when(quadrant === 2.B(2)) {
      when(funct3 === 0.B(3)) {
        io.legal := !sign
        io.hint := (rd === 0.B(5)) | (rs2 === 0.B(5))
        io.instruction := (0.B(7) ## rs2 ## rd ## 1.B(3) ## rd ## 0x13.B(7)).asUInt
      }
      when(funct3 === 2.B(3)) {
        io.legal := rd =/= 0.B(5)
        io.instruction := (stackLoad ## 2.B(5) ## 2.B(3) ## rd ## 3.B(7)).asUInt
      }
      when(funct3 === 4.B(3)) {
        io.legal := true.B
        when(rs2 === 0.B(5)) {
          io.legal := sign | (rd =/= 0.B(5))
          io.instruction := (0.B(12) ## rd ## 0.B(3) ## sign.?(1.B(5), 0.B(5)) ## 0x67.B(7)).asUInt
          when(sign & (rd === 0.B(5))) { io.instruction := 0x00100073.U(32) }
        }.otherwise {
          io.hint := rd === 0.B(5)
          io.instruction := (0.B(7) ## rs2 ## sign.?(rd, 0.B(5)) ## 0.B(3) ## rd ## 0x33.B(7)).asUInt
        }
      }
      when(funct3 === 6.B(3)) {
        io.legal := true.B
        io.instruction := (stackStore.bits(11, 5) ## rs2 ## 2.B(5) ## 2.B(3) ##
          stackStore.bits(4, 0) ## 0x23.B(7)).asUInt
      }
    }
    when(!io.legal) {
      io.instruction := 0.U(32)
      io.hint := false.B
    }
