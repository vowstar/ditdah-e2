// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*

class PlatformIO(p: PlatformParameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val dmi = Option.when(p.core.enableDebug)(Flipped(new DmiPort))
  val tick = Flipped(Bool())
  val externalInterrupt = Flipped(Bool())
  val transmit = Aligned(new Channel(UInt(8)))
  val axi = Aligned(new AxiLitePort)
  val retire = Aligned(new Retirement)
  val interrupt = Aligned(new InterruptEvent)
  val mulDiv = Aligned(new ArithmeticActivity)
  val sleeping = Aligned(Bool())
  val loadUse = Aligned(Bool())
  val forward = Aligned(Bool())
  val redirect = Aligned(Bool())
  val memoryWait = Aligned(Bool())
  val timeValue = Aligned(UInt(64))
  val timerInterrupt = Aligned(Bool())
  val softwareInterrupt = Aligned(Bool())

@generator
object DitDahE2Platform extends Generator[PlatformParameters, PlatformLayers, PlatformIO, PlatformProbe]:
  override def moduleName(p: PlatformParameters): String = "DitDahE2Platform"
  def architecture(p: PlatformParameters) =
    val io = summon[Interface[PlatformIO]]
    val core = DitDahE2.instantiate(p.core)
    val router = MemoryRouter.instantiate(p)
    val bus = AxiLite.instantiate(p.core)
    val console = Console.instantiate(p.core)
    val timer = MachineTimer.instantiate(p.core)
    core.io.clock := io.clock
    core.io.reset := io.reset
    val platformReset = Wire(Reset())
    platformReset := io.reset
    if p.core.enableDebug then
      core.io.dmi.get :<>= io.dmi.get
      platformReset := (io.reset.asBool | core.io.systemReset.get).asReset
    router.io.clock := io.clock
    router.io.reset := platformReset
    bus.io.clock := io.clock
    bus.io.reset := platformReset
    console.io.clock := io.clock
    console.io.reset := platformReset
    timer.io.clock := io.clock
    timer.io.reset := platformReset
    router.io.instruction :<>= core.io.instruction
    router.io.data :<>= core.io.data
    bus.io.instruction :<>= router.io.memoryInstruction
    bus.io.data :<>= router.io.memoryData
    console.io.memory :<>= router.io.console
    timer.io.memory :<>= router.io.timer
    io.axi :<>= bus.io.axi
    io.transmit :<>= console.io.transmit
    timer.io.tick := io.tick
    core.io.timeValue := timer.io.timeValue
    core.io.interrupts.software := timer.io.softwareInterrupt
    core.io.interrupts.timer := timer.io.timerInterrupt
    core.io.interrupts.external := io.externalInterrupt
    io.timeValue := timer.io.timeValue
    io.timerInterrupt := timer.io.timerInterrupt
    io.softwareInterrupt := timer.io.softwareInterrupt
    io.retire :<= core.io.retire
    io.interrupt :<= core.io.interrupt
    io.mulDiv :<= core.io.mulDiv
    io.sleeping := core.io.sleeping
    io.loadUse := core.io.loadUse
    io.forward := core.io.forward
    io.redirect := core.io.redirect
    io.memoryWait := core.io.memoryWait
