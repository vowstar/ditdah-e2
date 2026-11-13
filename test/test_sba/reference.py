# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Transaction-level Debug 1.0 system-bus register and byte-memory model.

The contract comes from the ratified Debug 1.0 DM system-bus register section:
https://docs.riscv.org/reference/debug/v1.0/debug_module.html
This model separates register effects from bus acceptance and completion.
"""

from collections import Counter
from dataclasses import dataclass

MASK32 = (1 << 32) - 1
SBCS, SBADDRESS, SBDATA = 0x38, 0x39, 0x3C
READ, WRITE = 1, 2


@dataclass(frozen=True)
class Transfer:
    address: int
    byte_count: int
    write: bool
    value: int

    @property
    def bus_payload(self):
        """Translate logical bytes to the existing little-endian MemoryPort."""
        lane = self.address % 4
        mask = sum(1 << (lane + index) for index in range(self.byte_count))
        return (self.address, 1, int(self.write),
                (self.value << (8 * lane)) & MASK32 if self.write else 0,
                mask if self.write else 0, {1: 0, 2: 1, 4: 2}[self.byte_count], 0)


@dataclass
class Pending:
    transfer: Transfer
    increment: bool
    accepted: bool = False
    discarded: bool = False


class SbaModel:
    """Model accepted DMI accesses without consulting implementation state."""

    def __init__(self):
        self.pending = None
        self.active = False
        self.counts = Counter()
        self.clear_registers()

    def clear_registers(self):
        self.address = self.data = self.error = 0
        self.data_mask = MASK32
        self.access_size = 2
        self.read_on_address = self.read_on_data = self.increment = False
        self.busy_error = False

    @property
    def busy(self):
        return self.pending is not None

    @property
    def idle(self):
        return not self.busy

    @property
    def offered(self):
        return self.pending is not None and not self.pending.accepted

    def activate(self, active):
        if type(active) is not bool:
            raise ValueError("Active must be Boolean")
        if not active:
            if self.pending is not None and not self.pending.discarded:
                self.pending.discarded = True
                self.counts["cancelled"] += 1
            self.clear_registers()
        self.active = active

    def cold_reset(self):
        if self.pending is not None:
            raise AssertionError("Cold reset requires the external bus to be idle")
        self.active = False
        self.clear_registers()

    def read_register(self, address, active=None):
        enabled = self.active if active is None else active
        if not enabled:
            return 0, MASK32
        if address == SBCS:
            # Capability constants describe the selected 32-bit physical port.
            value = (1 << 29) | (32 << 5) | 0b111
            value |= int(self.busy_error) << 22 | int(self.busy) << 21
            value |= int(self.read_on_address) << 20 | self.access_size << 17
            value |= int(self.increment) << 16 | int(self.read_on_data) << 15
            value |= self.error << 12
            return value, MASK32
        if address == SBADDRESS:
            return self.address, MASK32
        if address == SBDATA:
            # Debug 1.0 leaves high bits unspecified after a subword read.
            return self.data, self.data_mask
        return 0, MASK32

    def _start(self, write):
        if self.error or self.busy_error:
            self.counts["errorInhibited"] += 1
            return
        if self.access_size not in (0, 1, 2):
            self.error = 4
            self.counts["unsupportedSizes"] += 1
            return
        width = 1 << self.access_size
        if self.address % width:
            self.error = 3
            self.counts["misaligned"] += 1
            return
        self.pending = Pending(Transfer(self.address, width, write, self.data), self.increment)
        self.counts["writes" if write else "reads"] += 1

    def access(self, address, operation, value=0):
        if any(type(item) is not int for item in (address, operation, value)):
            raise ValueError("DMI fields must be integers")
        if not 0 <= address < 128 or not 0 <= operation < 4 or not 0 <= value <= MASK32:
            raise ValueError("DMI field exceeds its declared width")
        result = self.read_register(address)
        if not self.active or operation not in (READ, WRITE):
            return result
        self.counts["dmiAccesses"] += 1
        if address == SBCS:
            if operation == WRITE:
                if self.busy:
                    # Debug 1.0 leaves this write undefined; the local contract ignores it.
                    self.counts["busyControlWritesIgnored"] += 1
                    return result
                self.busy_error &= not bool(value & (1 << 22))
                self.error &= ~(value >> 12 & 7)
                self.read_on_address = bool(value & (1 << 20))
                self.access_size = value >> 17 & 7
                self.increment = bool(value & (1 << 16))
                self.read_on_data = bool(value & (1 << 15))
            return result
        if address == SBADDRESS:
            if operation == WRITE:
                if self.busy:
                    self.busy_error = True
                    self.counts["busyConflicts"] += 1
                    return result
                self.address = value
                if self.read_on_address:
                    self._start(False)
            return result
        if address != SBDATA:
            return result
        if self.error or self.busy_error:
            self.counts["errorInhibited"] += 1
            return result
        if self.busy:
            self.busy_error = True
            self.counts["busyConflicts"] += 1
            return result
        if operation == WRITE:
            self.data, self.data_mask = value, MASK32
            self._start(True)
        elif self.read_on_data:
            self._start(False)
        return result

    def accept_bus_request(self, payload):
        if not self.offered:
            raise AssertionError("Bus request has no unaccepted transaction owner")
        expected = self.pending.transfer.bus_payload
        comparable = tuple(payload)
        if not self.pending.transfer.write:
            comparable = (*comparable[:3], 0, *comparable[4:])
        if comparable != expected:
            raise AssertionError("Bus request differs from the logical byte transaction")
        self.pending.accepted = True
        self.counts["busAccepted"] += 1

    def complete_bus(self, data, fault=False):
        if type(data) is not int or not 0 <= data <= MASK32 or type(fault) is not bool:
            raise ValueError("Memory response has invalid data or fault fields")
        if self.pending is None or not self.pending.accepted:
            self.counts["unownedResponses"] += 1
            return
        pending, self.pending = self.pending, None
        self.counts["busCompleted"] += 1
        if pending.discarded or not self.active:
            self.counts["discardedResults"] += 1
            return
        if fault:
            self.error = 2
            self.counts["busFaults"] += 1
            return
        transfer = pending.transfer
        if not transfer.write:
            bits = 8 * transfer.byte_count
            self.data_mask = (1 << bits) - 1
            self.data = data >> (8 * (transfer.address % 4)) & self.data_mask
        if pending.increment:
            self.address = (transfer.address + transfer.byte_count) & MASK32
            self.counts["increments"] += 1


class ByteMemory:
    """Score bus data against addressed bytes rather than RTL packing expressions."""

    def __init__(self):
        self.bytes = {}

    def byte(self, address):
        address &= MASK32
        return self.bytes.get(address, (address ^ (address >> 8) ^ 0xA5) & 0xFF)

    def response(self, transfer, fault=False):
        if transfer.write and not fault:
            for index in range(transfer.byte_count):
                self.bytes[(transfer.address + index) & MASK32] = transfer.value >> (index * 8) & 0xFF
        base = transfer.address & ~3
        return sum(self.byte(base + index) << (8 * index) for index in range(4))
