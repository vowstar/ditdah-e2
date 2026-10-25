// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class PmpAccess extends Bundle:
  val address = Flipped(UInt(32))
  val size = Flipped(UInt(2))
  val machine = Flipped(Bool())
  val kind = Flipped(UInt(2))
  val allowed = Aligned(Bool())

class PmpIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val address = Flipped(UInt(12))
  val readData = Aligned(UInt(32))
  val implemented = Aligned(Bool())
  val commitWrite = Flipped(Bool())
  val writeData = Flipped(UInt(32))
  val instruction = Aligned(new PmpAccess)
  val data = Aligned(new PmpAccess)
