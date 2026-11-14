// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@upickle.implicits.serializeDefaults(true)
case class AtomicParameters(baseAddress: Long = 0, sizeBytes: Int = 4096, readLatency: Int = 1) extends Parameter:
  require(baseAddress >= 0 && baseAddress <= 0xffffffffL && (baseAddress & 3) == 0,
    "Atomic memory base must be an aligned RV32 address")
  require(sizeBytes >= 4 && (sizeBytes & 3) == 0 && baseAddress + sizeBytes <= 0x100000000L,
    "Atomic memory must contain complete words within RV32")
  val storage = SramParameters(depth = sizeBytes / 4, readLatency = readLatency)

given upickle.default.ReadWriter[AtomicParameters] = upickle.default.macroRW

class AtomicLayers(p: AtomicParameters) extends LayerInterface(p):
  def layers = Seq.empty
class AtomicProbe(p: AtomicParameters) extends DVBundle[AtomicParameters, AtomicLayers](p)

class AtomicRequest extends Bundle:
  val address: BundleField[UInt] = Aligned(UInt(32))
  val machine: BundleField[Bool] = Aligned(Bool())
  val write: BundleField[Bool] = Aligned(Bool())
  val data: BundleField[UInt] = Aligned(UInt(32))
  val mask: BundleField[UInt] = Aligned(UInt(4))
  val size: BundleField[UInt] = Aligned(UInt(2))
  val operation: BundleField[UInt] = Aligned(UInt(4))

class AtomicPort extends Bundle:
  val request: BundleField[Channel[AtomicRequest]] = Aligned(new Channel(new AtomicRequest))
  val response: BundleField[Channel[MemoryResponse]] = Flipped(new Channel(new MemoryResponse))

class AtomicMemoryIO(p: AtomicParameters) extends HWBundle(p):
  val clock: BundleField[Clock] = Flipped(Clock())
  val reset: BundleField[Reset] = Flipped(Reset())
  val clearReservation: BundleField[Bool] = Flipped(Bool())
  val instruction: BundleField[AtomicPort] = Flipped(new AtomicPort)
  val data: BundleField[AtomicPort] = Flipped(new AtomicPort)
  val debug: BundleField[AtomicPort] = Flipped(new AtomicPort)
  val competitor: BundleField[AtomicPort] = Flipped(new AtomicPort)

case class AtomicSramParameters(WORDS: Int, ADDRESS_WIDTH: Int, READ_LATENCY: Int) extends VerilogParameter

@generator
object AtomicSram extends VerilogWrapper[SramParameters, SramLayers, SramIO, SramProbe, AtomicSramParameters]:
  def verilogModuleName(p: SramParameters): String = "DitDahE2AtomicSram"
  def verilogParameter(p: SramParameters) =
    require(p.width == 32 && p.maskGranularity == 8, "Atomic storage requires four byte lanes")
    AtomicSramParameters(p.depth, p.addressWidth, p.readLatency)
