// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.Parameter

@upickle.implicits.serializeDefaults(true)
case class Parameters(resetVector: Long = 0, enableM: Boolean = false, enableC: Boolean = false) extends Parameter:
  require(resetVector >= 0 && resetVector <= 0xffffffffL, "resetVector must fit RV32")
  require((resetVector & (if enableC then 1 else 3)) == 0, "resetVector must satisfy instruction alignment")

given upickle.default.ReadWriter[Parameters] = upickle.default.macroRW
