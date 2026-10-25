// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
package ditdah_e2

import me.jiuyang.zaozi.*

given mainargs.TokensReader.Simple[Parameters] with
  def shortName: String = "core-json"
  def read(tokens: Seq[String]): Either[String, Parameters] =
    tokens match
      case Seq(value) => scala.util.Try(upickle.default.read[Parameters](value)).toEither.left.map(_.getMessage)
      case _ => Left("Expected one core configuration object")

@upickle.implicits.serializeDefaults(true)
case class PlatformParameters(
  core: Parameters,
  romBase: Long, romSize: Long,
  ramBase: Long, ramSize: Long,
  consoleBase: Long, consoleSize: Long,
  timerBase: Long, timerSize: Long
) extends Parameter:
  private val regions = Seq((romBase, romSize), (ramBase, ramSize),
    (consoleBase, consoleSize), (timerBase, timerSize))
  require(regions.forall { case (base, size) =>
    base >= 0 && base <= 0xffffffffL && size >= 4 && size <= 0x100000000L &&
      (base & 3) == 0 && (size & 3) == 0 &&
      base + size <= 0x100000000L
  }, "Platform regions must fit RV32 and contain whole words")
  require(regions.combinations(2).forall { pair =>
    val (a, b) = (pair.head, pair.last)
    a._1 + a._2 <= b._1 || b._1 + b._2 <= a._1
  }, "Platform regions must not overlap")
  require(consoleSize >= 8 && timerSize >= 20, "Device regions must contain their registers")
  require(core.resetVector >= romBase && core.resetVector < romBase + romSize,
    "Platform reset vector must be inside ROM")

given upickle.default.ReadWriter[PlatformParameters] = upickle.default.macroRW

class PlatformLayers(p: PlatformParameters) extends LayerInterface(p):
  def layers = Seq.empty
class PlatformProbe(p: PlatformParameters) extends DVBundle[PlatformParameters, PlatformLayers](p)
