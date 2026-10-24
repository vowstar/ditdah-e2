// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class AxiLiteAddress extends Bundle:
  val address = Aligned(UInt(32))
  val protection = Aligned(UInt(3))

class AxiLiteWriteData extends Bundle:
  val data = Aligned(UInt(32))
  val strobe = Aligned(UInt(4))

class AxiLiteWriteResponse extends Bundle:
  val response = Aligned(UInt(2))

class AxiLiteReadResponse extends Bundle:
  val data = Aligned(UInt(32))
  val response = Aligned(UInt(2))

class AxiLitePort extends Bundle:
  val aw = Aligned(new Channel(new AxiLiteAddress))
  val w = Aligned(new Channel(new AxiLiteWriteData))
  val b = Flipped(new Channel(new AxiLiteWriteResponse))
  val ar = Aligned(new Channel(new AxiLiteAddress))
  val r = Flipped(new Channel(new AxiLiteReadResponse))

class AxiLiteIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val instruction = Flipped(new MemoryPort)
  val data = Flipped(new MemoryPort)
  val axi = Aligned(new AxiLitePort)
