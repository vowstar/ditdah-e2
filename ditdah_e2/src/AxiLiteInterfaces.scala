// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
import me.jiuyang.stdlib.*

class AxiLiteAddress extends Bundle:
  val address: BundleField[UInt] = Aligned(UInt(32))
  val protection: BundleField[UInt] = Aligned(UInt(3))

class AxiLiteWriteData extends Bundle:
  val data: BundleField[UInt] = Aligned(UInt(32))
  val strobe: BundleField[UInt] = Aligned(UInt(4))

class AxiLiteWriteResponse extends Bundle:
  val response: BundleField[UInt] = Aligned(UInt(2))

class AxiLiteReadResponse extends Bundle:
  val data: BundleField[UInt] = Aligned(UInt(32))
  val response: BundleField[UInt] = Aligned(UInt(2))

class AxiLitePort extends Bundle:
  val aw: BundleField[DecoupledIO[AxiLiteAddress]] = Aligned(Decoupled(new AxiLiteAddress))
  val w: BundleField[DecoupledIO[AxiLiteWriteData]] = Aligned(Decoupled(new AxiLiteWriteData))
  val b: BundleField[DecoupledIO[AxiLiteWriteResponse]] = Flipped(Decoupled(new AxiLiteWriteResponse))
  val ar: BundleField[DecoupledIO[AxiLiteAddress]] = Aligned(Decoupled(new AxiLiteAddress))
  val r: BundleField[DecoupledIO[AxiLiteReadResponse]] = Flipped(Decoupled(new AxiLiteReadResponse))

class AxiLiteIO(p: Parameters) extends HWBundle(p):
  val clock: BundleField[Clock] = Flipped(Clock())
  val reset: BundleField[Reset] = Flipped(Reset())
  val instruction: BundleField[MemoryPort] = Flipped(new MemoryPort)
  val data: BundleField[MemoryPort] = Flipped(new MemoryPort)
  val axi: BundleField[AxiLitePort] = Aligned(new AxiLitePort)
