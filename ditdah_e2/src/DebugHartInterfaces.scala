// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

@upickle.implicits.serializeDefaults(true)
case class DebugHartParameters(resetVector: Long = 0, enableC: Boolean = false, protectedMode: Boolean = false) extends Parameter:
  require(resetVector >= 0 && resetVector <= 0xffffffffL, "Debug reset vector must fit RV32")
  require((resetVector & (if enableC then 1 else 3)) == 0, "Debug reset vector must satisfy instruction alignment")

given upickle.default.ReadWriter[DebugHartParameters] = upickle.default.macroRW

class DebugHartLayers(p: DebugHartParameters) extends LayerInterface(p):
  def layers = Seq.empty
class DebugHartProbe(p: DebugHartParameters) extends DVBundle[DebugHartParameters, DebugHartLayers](p)

class DebugCoreControl extends Bundle:
  val empty = Flipped(Bool())
  val fetchIdle = Flipped(Bool())
  val architecturalPc = Flipped(UInt(32))
  val userMode = Flipped(Bool())
  val completed = Flipped(Bool())
  val breakpoint = Flipped(Bool())
  val breakpointPc = Flipped(UInt(32))
  val stop = Aligned(Bool())
  val resume = Aligned(Bool())
  val resumePc = Aligned(UInt(32))
  val resumeUser = Aligned(Bool())
  val coreReset = Aligned(Bool())
  val singleStep = Aligned(Bool())
  val ebreakMachine = Aligned(Bool())
  val ebreakUser = Aligned(Bool())
  val freezeCounters = Aligned(Bool())

class DebugRegisterBackend extends Bundle:
  val register = Aligned(UInt(16))
  val writeRequested = Aligned(Bool())
  val writePulse = Aligned(Bool())
  val writeData = Aligned(UInt(32))
  val readData = Flipped(UInt(32))
  val error = Flipped(Bool())

class DebugMemoryProtection extends Bundle:
  val address = Aligned(UInt(32))
  val size = Aligned(UInt(2))
  val write = Aligned(Bool())
  val allowed = Flipped(Bool())
  val machine = Flipped(Bool())

class DebugHartIO(p: DebugHartParameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val debug = Flipped(new DebugHartPort)
  val core = Aligned(new DebugCoreControl)
  val backend = Aligned(new DebugRegisterBackend)
  val protection = Aligned(new DebugMemoryProtection)
  val memory = Aligned(new MemoryPort)
