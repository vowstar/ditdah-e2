// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*
import me.jiuyang.zaozi.default.{*, given}

@generator
object Sram extends VerilogWrapper[SramParameters, SramLayers, SramIO, SramProbe, SramVerilogParameters]:
  def verilogModuleName(p: SramParameters): String = "DitDahE2Sram"
  def verilogParameter(p: SramParameters) =
    SramVerilogParameters(p.depth, p.width, p.maskGranularity, p.readLatency, p.addressWidth)
