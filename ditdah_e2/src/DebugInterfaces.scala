// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class DebugHartRequest extends Bundle:
  val memory = Aligned(Bool())
  val write = Aligned(Bool())
  val size = Aligned(UInt(2))
  val register = Aligned(UInt(16))
  val address = Aligned(UInt(32))
  val data = Aligned(UInt(32))

class DebugHartResponse extends Bundle:
  val data = Aligned(UInt(32))
  val error = Aligned(UInt(3))

class DebugHartControl extends Bundle:
  val active = Aligned(Bool())
  val halt = Aligned(Bool())
  val resume = Aligned(Bool())
  val reset = Aligned(Bool())
  val haltOnReset = Aligned(Bool())

class DebugHartStatus extends Bundle:
  val halted = Aligned(Bool())
  val running = Aligned(Bool())
  val unavailable = Aligned(Bool())
  val resetEvent = Aligned(Bool())
  val resumeAck = Aligned(Bool())
  val resetPending = Aligned(Bool())

class DebugHartPort extends Bundle:
  val request = Aligned(new Channel(new DebugHartRequest))
  val response = Flipped(new Channel(new DebugHartResponse))
  val control = Aligned(new DebugHartControl)
  val status = Flipped(new DebugHartStatus)

class DebugModuleIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val dmi = Flipped(new DmiPort)
  val hart = Aligned(new DebugHartPort)
