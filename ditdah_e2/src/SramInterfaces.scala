// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@upickle.implicits.serializeDefaults(true)
case class SramParameters(depth: Int = 1024, width: Int = 32, maskGranularity: Int = 8,
                          readLatency: Int = 1) extends Parameter:
  require(depth > 0, "SRAM depth must be positive")
  require(width > 0 && maskGranularity > 0 && maskGranularity % 8 == 0 && width % maskGranularity == 0,
    "SRAM masks must partition the word into complete byte groups")
  require(readLatency == 1 || readLatency == 2, "SRAM read latency must be one or two cycles")
  val addressWidth = math.max(1, 32 - Integer.numberOfLeadingZeros(depth - 1))
  val maskWidth = width / maskGranularity

given upickle.default.ReadWriter[SramParameters] = upickle.default.macroRW

class SramLayers(p: SramParameters) extends LayerInterface(p):
  def layers = Seq.empty
class SramProbe(p: SramParameters) extends DVBundle[SramParameters, SramLayers](p)

class SramIO(p: SramParameters) extends HWBundle(p):
  val clock: BundleField[Clock] = Flipped(Clock())
  val address: BundleField[UInt] = Flipped(UInt(p.addressWidth))
  val readEnable: BundleField[Bool] = Flipped(Bool())
  val writeMask: BundleField[UInt] = Flipped(UInt(p.maskWidth))
  val writeData: BundleField[UInt] = Flipped(UInt(p.width))
  val readData: BundleField[UInt] = Aligned(UInt(p.width))

case class SramVerilogParameters(DEPTH: Int, WIDTH: Int, MASK_GRANULARITY: Int,
                                READ_LATENCY: Int, ADDRESS_WIDTH: Int) extends VerilogParameter
