// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@upickle.implicits.serializeDefaults(true)
case class LocalMemoryParameters(
  baseAddress: Long,
  sizeBytes: Int,
  readLatency: Int = 1,
  useSram: Boolean = true
) extends Parameter:
  require(baseAddress >= 0 && baseAddress <= 0xffffffffL && (baseAddress & 3) == 0,
    "Local memory base must be an aligned RV32 address")
  require(sizeBytes >= 4 && (sizeBytes & 3) == 0 && baseAddress + sizeBytes <= 0x100000000L,
    "Local memory must contain complete words within RV32")
  require(readLatency == 1 || readLatency == 2, "Local memory read latency must be one or two cycles")

given upickle.default.ReadWriter[LocalMemoryParameters] = upickle.default.macroRW

class LocalMemoryLayers(p: LocalMemoryParameters) extends LayerInterface(p):
  def layers = Seq.empty
class LocalMemoryProbe(p: LocalMemoryParameters) extends DVBundle[LocalMemoryParameters, LocalMemoryLayers](p)

class LocalMemoryIO(p: LocalMemoryParameters) extends HWBundle(p):
  val clock: BundleField[Clock] = Flipped(Clock())
  val reset: BundleField[Reset] = Flipped(Reset())
  val instruction: BundleField[MemoryPort] = Flipped(new MemoryPort)
  val data: BundleField[MemoryPort] = Flipped(new MemoryPort)
