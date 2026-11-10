// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.Parameter

@upickle.implicits.serializeDefaults(true)
case class Parameters(resetVector: Long = 0, enableM: Boolean = true, enableC: Boolean = true,
                      protectedMode: Boolean = false, enableDebug: Boolean = false, enableA: Boolean = false,
                      enableZba: Boolean = false, enableZbb: Boolean = false, enableZbs: Boolean = false,
                      enableJtag: Boolean = false, jtagIdcode: Option[Long] = None) extends Parameter:
  require(resetVector >= 0 && resetVector <= 0xffffffffL, "resetVector must fit RV32")
  require((resetVector & (if enableC then 1 else 3)) == 0, "resetVector must satisfy instruction alignment")
  require(!enableJtag || enableDebug, "JTAG transport requires Debug")
  require(jtagIdcode.forall(id => id > 0 && id <= 0xffffffffL && (id & 1) == 1),
    "JTAG IDCODE must be an odd unsigned 32-bit value")
  require(!enableJtag || jtagIdcode.nonEmpty, "JTAG transport requires an explicit IDCODE")

given upickle.default.ReadWriter[Parameters] = upickle.default.macroRW
