// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@upickle.implicits.serializeDefaults(true)
case class AtomicParameters(baseAddress: Long = 0, sizeBytes: Int = 4096) extends Parameter:
  require(baseAddress >= 0 && baseAddress <= 0xffffffffL && (baseAddress & 3) == 0,
    "Atomic memory base must be an aligned RV32 address")
  require(sizeBytes >= 4 && (sizeBytes & 3) == 0 && baseAddress + sizeBytes <= 0x100000000L,
    "Atomic memory must contain complete words within RV32")
  val words = sizeBytes / 4
  val addressWidth = math.max(1, 32 - Integer.numberOfLeadingZeros(words - 1))

given upickle.default.ReadWriter[AtomicParameters] = upickle.default.macroRW

class AtomicLayers(p: AtomicParameters) extends LayerInterface(p):
  def layers = Seq.empty
class AtomicProbe(p: AtomicParameters) extends DVBundle[AtomicParameters, AtomicLayers](p)

class AtomicRequest extends Bundle:
  val address = Aligned(UInt(32))
  val machine = Aligned(Bool())
  val write = Aligned(Bool())
  val data = Aligned(UInt(32))
  val mask = Aligned(UInt(4))
  val size = Aligned(UInt(2))
  val operation = Aligned(UInt(4))

class AtomicPort extends Bundle:
  val request = Aligned(new Channel(new AtomicRequest))
  val response = Flipped(new Channel(new MemoryResponse))

class AtomicMemoryIO(p: AtomicParameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val clearReservation = Flipped(Bool())
  val instruction = Flipped(new AtomicPort)
  val data = Flipped(new AtomicPort)
  val debug = Flipped(new AtomicPort)
  val competitor = Flipped(new AtomicPort)

class AtomicSramIO(p: AtomicParameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val address = Flipped(UInt(p.addressWidth))
  val readEnable = Flipped(Bool())
  val writeMask = Flipped(UInt(4))
  val writeData = Flipped(UInt(32))
  val readData = Aligned(UInt(32))

case class AtomicSramParameters(WORDS: Int, ADDRESS_WIDTH: Int) extends VerilogParameter

@generator
object AtomicSram extends VerilogWrapper[AtomicParameters, AtomicLayers, AtomicSramIO, AtomicProbe, AtomicSramParameters]:
  def verilogModuleName(p: AtomicParameters): String = "DitDahE2AtomicSram"
  def verilogParameter(p: AtomicParameters) = AtomicSramParameters(p.words, p.addressWidth)
