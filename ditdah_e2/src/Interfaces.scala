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

class DmiRequest extends Bundle:
  val address = Aligned(UInt(7))
  val data = Aligned(UInt(32))
  val op = Aligned(UInt(2))

class DmiResponse extends Bundle:
  val data = Aligned(UInt(32))
  val status = Aligned(UInt(2))

class DmiPort extends Bundle:
  val request = Aligned(new Channel(new DmiRequest))
  val response = Flipped(new Channel(new DmiResponse))

class MemoryRequest extends Bundle:
  val address = Aligned(UInt(32))
  val machine = Aligned(Bool())
  val write = Aligned(Bool())
  val data = Aligned(UInt(32))
  val mask = Aligned(UInt(4))
  val size = Aligned(UInt(2))
  val operation = Aligned(UInt(4))

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
  val userMode = Aligned(Bool())
  val csrMstatus = Aligned(new CsrState)
  val csrMepc = Aligned(new CsrState)
  val csrMcause = Aligned(new CsrState)
  val csrMtval = Aligned(new CsrState)
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

class CsrState(width: Int = 32) extends Bundle:
  val before = Aligned(UInt(width))
  val after = Aligned(UInt(width))
  val writeMask = Aligned(UInt(width))

class CsrAccess extends Bundle:
  val valid = Aligned(Bool())
  val address = Aligned(UInt(12))
  val readMask = Aligned(UInt(32))
  val writeMask = Aligned(UInt(32))
  val readData = Aligned(UInt(32))
  val writeData = Aligned(UInt(32))

class Completion extends Bundle:
  val instruction = Aligned(new Instruction)
  val rs1 = Aligned(UInt(5))
  val rs1Data = Aligned(UInt(32))
  val rs2 = Aligned(UInt(5))
  val rs2Data = Aligned(UInt(32))
  val userMode = Aligned(Bool())
  val debugBreak = Aligned(Bool())
  val nextPc = Aligned(UInt(32))
  val rd = Aligned(UInt(5))
  val writes = Aligned(Bool())
  val value = Aligned(UInt(32))
  val load = Aligned(Bool())
  val store = Aligned(Bool())
  val address = Aligned(UInt(32))
  val atomicOperation = Aligned(UInt(4))
  val storeData = Aligned(UInt(32))
  val size = Aligned(UInt(2))
  val unsignedLoad = Aligned(Bool())
  val csr = Aligned(Bool())
  val csrAddress = Aligned(UInt(12))
  val csrOperation = Aligned(UInt(2))
  val csrOperand = Aligned(UInt(32))
  val csrWrite = Aligned(Bool())
  val csrRead = Aligned(Bool())
  val mret = Aligned(Bool())
  val wfi = Aligned(Bool())
  val fenceI = Aligned(Bool())
  val trap = Aligned(Bool())
  val cause = Aligned(UInt(32))
  val tval = Aligned(UInt(32))

class Retirement extends Bundle:
  val order = Aligned(UInt(64))
  val length = Aligned(UInt(3))
  val insn = Aligned(UInt(32))
  val intr = Aligned(Bool())
  val rs1 = Aligned(UInt(5))
  val rs1Data = Aligned(UInt(32))
  val rs2 = Aligned(UInt(5))
  val rs2Data = Aligned(UInt(32))
  val memoryAddress = Aligned(UInt(32))
  val memoryReadMask = Aligned(UInt(4))
  val memoryWriteMask = Aligned(UInt(4))
  val memoryReadData = Aligned(UInt(32))
  val memoryWriteData = Aligned(UInt(32))
  val memoryOperation = Aligned(UInt(4))
  val memoryResponse = Aligned(UInt(32))
  val memoryOperand = Aligned(UInt(32))
  val memoryFault = Aligned(Bool())
  val faultReadMask = Aligned(UInt(4))
  val faultWriteMask = Aligned(UInt(4))
  val misa = Aligned(UInt(32))
  val csr = Aligned(new CsrAccess)
  val csrMstatus = Aligned(new CsrState)
  val csrMepc = Aligned(new CsrState)
  val csrMcause = Aligned(new CsrState)
  val csrMtval = Aligned(new CsrState)
  val csrCycle = Aligned(new CsrState(64))
  val csrInstret = Aligned(new CsrState(64))
  val csrTime = Aligned(UInt(64))
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
  val dmi = Option.when(p.enableDebug)(Flipped(new DmiPort))
  val systemReset = Option.when(p.enableDebug)(Aligned(Bool()))
  val reservationClear = Option.when(p.enableA)(Aligned(Bool()))
  val dataDebug = Option.when(p.enableA)(Aligned(Bool()))
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
