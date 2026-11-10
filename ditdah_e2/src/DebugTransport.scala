// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}
import me.jiuyang.zaozi.reftpe.*
import me.jiuyang.zaozi.valuetpe.*
import java.lang.foreign.Arena
import org.llvm.mlir.scalalib.capi.ir.{Block, Context}

class DebugTransportIO(p: Parameters) extends HWBundle(p):
  val clock = Flipped(Clock())
  val reset = Flipped(Reset())
  val jtag = Aligned(new JtagPort)
  val dmi = Aligned(new DmiPort)

@generator
object DitDahE2DebugTransport extends Generator[Parameters, UnitLayers, DebugTransportIO, UnitProbe]:
  override def moduleName(p: Parameters): String = "DitDahE2DebugTransport"
  def architecture(p: Parameters) =
    val io = summon[Interface[DebugTransportIO]]
    val dtm = DitDahE2JtagDtm.instantiate(p)
    val bridge = DitDahE2DmiBridge.instantiate(p)
    dtm.io.tck := io.jtag.tck
    dtm.io.reset := io.reset
    dtm.io.trstN := io.jtag.trstN
    dtm.io.tms := io.jtag.tms
    dtm.io.tdi := io.jtag.tdi
    io.jtag.tdo := dtm.io.tdo
    io.jtag.tdoEnable := dtm.io.tdoEnable
    bridge.io.clock := io.clock
    bridge.io.tck := io.jtag.tck
    bridge.io.reset := io.reset
    bridge.io.upstream :<>= dtm.io.dmi
    io.dmi :<>= bridge.io.downstream

  def connect(p: Parameters, clock: Ref[Clock], reset: Ref[Reset], pins: Ref[JtagPort], dmi: Ref[DmiPort])
             (using Arena, Context, Block, InstanceContext): Unit =
    val transport = DitDahE2DebugTransport.instantiate(p)
    transport.io.clock := clock
    transport.io.reset := reset
    transport.io.jtag.tck := pins.tck
    transport.io.jtag.trstN := pins.trstN
    transport.io.jtag.tms := pins.tms
    transport.io.jtag.tdi := pins.tdi
    pins.tdo := transport.io.jtag.tdo
    pins.tdoEnable := transport.io.jtag.tdoEnable
    dmi :<>= transport.io.dmi
