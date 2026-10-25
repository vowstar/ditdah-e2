// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class UnitLayers(p: Parameters) extends LayerInterface(p):
  def layers = Seq.empty
class UnitProbe(p: Parameters) extends DVBundle[Parameters, UnitLayers](p)

class Channel[T <: Data](payload: T) extends Bundle:
  val valid = Aligned(Bool())
  val ready = Flipped(Bool())
  val bits = Aligned(payload)

class MemoryRequest extends Bundle:
  val address = Aligned(UInt(32))
  val machine = Aligned(Bool())
  val write = Aligned(Bool())
  val data = Aligned(UInt(32))
  val mask = Aligned(UInt(4))
  val size = Aligned(UInt(2))

class MemoryResponse extends Bundle:
  val data = Aligned(UInt(32))
  val fault = Aligned(Bool())

class MemoryPort extends Bundle:
  val request = Aligned(new Channel(new MemoryRequest))
  val response = Flipped(new Channel(new MemoryResponse))

class InterruptLevels extends Bundle:
  val software = Aligned(Bool())
  val timer = Aligned(Bool())
  val external = Aligned(Bool())

class InterruptEvent extends Bundle:
  val valid = Aligned(Bool())
  val pc = Aligned(UInt(32))
  val target = Aligned(UInt(32))
  val cause = Aligned(UInt(32))

class ArithmeticActivity extends Bundle:
  val start = Aligned(Bool())
  val resultValid = Aligned(Bool())
  val finish = Aligned(Bool())
  val cancel = Aligned(Bool())
  val pc = Aligned(UInt(32))
  val value = Aligned(UInt(32))

class Instruction extends Bundle:
  val pc = Aligned(UInt(32))
  val word = Aligned(UInt(32))
  val length = Aligned(UInt(3))
  val fault = Aligned(Bool())
  val faultAddress = Aligned(UInt(32))

class Completion extends Bundle:
  val instruction = Aligned(new Instruction)
  val userMode = Aligned(Bool())
  val nextPc = Aligned(UInt(32))
  val rd = Aligned(UInt(5))
  val writes = Aligned(Bool())
  val value = Aligned(UInt(32))
  val load = Aligned(Bool())
  val store = Aligned(Bool())
  val address = Aligned(UInt(32))
  val storeData = Aligned(UInt(32))
  val size = Aligned(UInt(2))
  val unsignedLoad = Aligned(Bool())
  val csr = Aligned(Bool())
  val csrAddress = Aligned(UInt(12))
  val csrOperation = Aligned(UInt(2))
  val csrOperand = Aligned(UInt(32))
  val csrWrite = Aligned(Bool())
  val mret = Aligned(Bool())
  val wfi = Aligned(Bool())
  val fenceI = Aligned(Bool())
  val trap = Aligned(Bool())
  val cause = Aligned(UInt(32))
  val tval = Aligned(UInt(32))

class Retirement extends Bundle:
  val valid = Aligned(Bool())
  val userMode = Aligned(Bool())
  val pc = Aligned(UInt(32))
  val word = Aligned(UInt(32))
  val nextPc = Aligned(UInt(32))
  val rd = Aligned(UInt(5))
  val writes = Aligned(Bool())
  val value = Aligned(UInt(32))
  val trap = Aligned(Bool())
  val cause = Aligned(UInt(32))
  val tval = Aligned(UInt(32))

class FetchIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val machine = Flipped(Bool())
  val redirect = Flipped(Bool())
  val target = Flipped(UInt(32))
  val pause = Flipped(Bool())
  val idle = Aligned(Bool())
  val memory = Aligned(new MemoryPort)
  val output = Aligned(new Channel(new Instruction))

class CoreIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val interrupts = Flipped(new InterruptLevels)
  val timeValue = Flipped(UInt(64))
  val instruction = Aligned(new MemoryPort)
  val data = Aligned(new MemoryPort)
  val retire = Aligned(new Retirement)
  val interrupt = Aligned(new InterruptEvent)
  val mulDiv = Aligned(new ArithmeticActivity)
  val sleeping = Aligned(Bool())
  val loadUse = Aligned(Bool())
  val forward = Aligned(Bool())
  val redirect = Aligned(Bool())
  val memoryWait = Aligned(Bool())
