// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@upickle.implicits.serializeDefaults(true)
case class BitParameters(enableZba: Boolean = false, enableZbb: Boolean = false,
                         enableZbs: Boolean = false) extends Parameter

given upickle.default.ReadWriter[BitParameters] = upickle.default.macroRW

class BitLayers(p: BitParameters) extends LayerInterface(p):
  def layers = Seq.empty
class BitProbe(p: BitParameters) extends DVBundle[BitParameters, BitLayers](p)

class BitIO(p: BitParameters) extends HWBundle(p):
  val word = Flipped(UInt(32))
  val a = Flipped(UInt(32))
  val b = Flipped(UInt(32))
  val valid = Aligned(Bool())
  val result = Aligned(UInt(32))
  val usesRs2 = Aligned(Bool())
