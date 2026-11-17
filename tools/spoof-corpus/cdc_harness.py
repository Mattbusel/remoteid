"""Runs cyber-defence-campus/droneRemoteIDSpoofer under a virtual clock and
writes what it would transmit to pcap files. Nothing is transmitted.

The spoofer's own code builds every frame: its CLI entry point is called
with real arguments, and only the operating system edges are replaced:

* the raw Wi-Fi socket and the Bluetooth HCI socket record frames instead
  of sending them (monitor mode setup and teardown are skipped);
* time.time / time.sleep / time.monotonic / datetime.now in the spoofer's
  modules read a virtual clock, and a cooperative scheduler runs one thread
  at a time, so a 40 second scenario takes a fraction of a second and the
  output is the same on every run;
* random is seeded.

Usage: python3 cdc_harness.py <path to the spoofer checkout> <out dir>
"""

import datetime as _dt
import os
import struct
import sys
import threading
import time as _real_time

START = 1794916800.0  # 2026-11-17 12:00:00 UTC
DURATION = 40.0

SCENARIOS = [
    # (output name, argv after the program name)
    ("cdc_wifi_random3.pcap", ["-i", "wlan0", "-r", "3", "-l", "47.3763", "8.5312"]),
    ("cdc_ble_legacy_random2.pcap", ["-i", "wlan0", "-t", "ble", "--ble-mode", "legacy", "-r", "2", "-l", "47.3763", "8.5312"]),
    ("cdc_wifi_same_mac.pcap", ["-i", "wlan0", "-t", "wifi", "-c", "scenarios/same_mac.json"]),
    ("cdc_wifi_slow_forward.pcap", ["-i", "wlan0", "-t", "wifi", "-c", "scenarios/slow_forward.json"]),
]


class VirtualClock:
    """A discrete event clock. Every participating thread blocks in sleep();
    when all of them are blocked, time jumps to the earliest wake-up and that
    thread runs alone."""

    def __init__(self, start, duration):
        self.start = start
        self.now = start
        self.limit = start + duration
        self.cv = threading.Condition()
        self.runnable = set()
        self.sleepers = {}
        self.seq = 0
        self.done = False

    def register(self, thread):
        with self.cv:
            self.runnable.add(thread)

    def unregister(self, thread):
        with self.cv:
            self.runnable.discard(thread)
            self.sleepers.pop(thread, None)
            self._advance()

    def time(self):
        return self.now

    def monotonic(self):
        return self.now - self.start + 1000.0

    def _advance(self):
        if self.done or not self.runnable:
            return
        if any(t not in self.sleepers for t in self.runnable):
            return
        thread, (wake, _) = min(self.sleepers.items(), key=lambda kv: kv[1])
        if wake > self.limit:
            self.done = True
            self.sleepers.clear()
            self.cv.notify_all()
            return
        self.now = max(self.now, wake)
        del self.sleepers[thread]
        self.cv.notify_all()

    def sleep(self, dt):
        me = threading.current_thread()
        if self.done:
            _real_time.sleep(0.001)
            if me is threading.main_thread():
                raise KeyboardInterrupt
            return
        with self.cv:
            if me not in self.runnable:
                self.runnable.add(me)
            self.seq += 1
            self.sleepers[me] = (self.now + max(float(dt), 0.0), self.seq)
            self._advance()
            while me in self.sleepers and not self.done:
                self.cv.wait()
        if self.done and me is threading.main_thread():
            raise KeyboardInterrupt


class Pcap:
    def __init__(self, path, linktype):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))

    def write(self, t, data):
        sec = int(t)
        usec = int(round((t - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self.f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
        self.f.write(data)

    def close(self):
        self.f.close()


def ble_crc24(pdu):
    """CRC-24 of a BLE link layer PDU (advertising channel init 0x555555)."""
    crc = 0x555555
    for byte in pdu:
        for bit in range(8):
            d = (byte >> bit) & 1
            c = (crc >> 23) & 1
            crc = (crc << 1) & 0xFFFFFF
            if c ^ d:
                crc ^= 0x00065B
    # Transmitted LSB first: reverse the 24 bits.
    out = 0
    for i in range(24):
        if crc & (1 << i):
            out |= 1 << (23 - i)
    return out.to_bytes(3, "little")


def run(repo, out_dir, name, argv):
    import random

    random.seed(20261117)
    clock = VirtualClock(START, DURATION)
    clock.register(threading.main_thread())

    class FakeTime:
        time = staticmethod(clock.time)
        sleep = staticmethod(clock.sleep)
        monotonic = staticmethod(clock.monotonic)
        perf_counter = staticmethod(clock.monotonic)

    class FakeDatetime(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return _dt.datetime.fromtimestamp(clock.now, tz)

    class TrackedThread(threading.Thread):
        def start(self):
            clock.register(self)
            super().start()

        def run(self):
            try:
                super().run()
            finally:
                clock.unregister(self)

    class FakeThreading:
        Thread = TrackedThread
        Lock = threading.Lock
        RLock = threading.RLock
        Condition = threading.Condition
        Event = threading.Event

    os.chdir(repo)
    sys.path.insert(0, repo)
    for mod in list(sys.modules):
        if mod.startswith("drone_rid_spoofer"):
            del sys.modules[mod]
    from drone_rid_spoofer import cli, messages, spoofer
    from drone_rid_spoofer.transport import ble, wifi

    for m in (spoofer, wifi, ble):
        m.time = FakeTime
    for m in (spoofer, messages):
        m.datetime = FakeDatetime
    for m in (wifi, ble):
        m.threading = FakeThreading

    frames = []

    class CaptureSocket:
        def __init__(self, kind):
            self.kind = kind

        def send(self, data):
            frames.append((clock.now, bytes(data)))
            return len(data)

        def close(self):
            pass

    def wifi_acquire(self):
        self._sock = CaptureSocket("wifi")

    wifi.WifiBackend._acquire = wifi_acquire
    wifi.restore_managed_mode = lambda *a, **k: None

    hci = {"addr": b"\0" * 6, "data": b"", "enabled": False}

    def ble_acquire(self):
        self._sock = CaptureSocket("hci")

    def send_hci(self, opcode, data):
        if opcode == ble.HCI_CMD_LE_SET_RANDOM_ADDR:
            hci["addr"] = bytes(data[:6])
        elif opcode == ble.HCI_CMD_LE_SET_ADV_DATA:
            hci["data"] = bytes(data[1 : 1 + data[0]])
        elif opcode == ble.HCI_CMD_LE_SET_ADV_ENABLE:
            if data[0] and not hci["enabled"]:
                # One ADV_NONCONN_IND per enable: the spoofer keeps each
                # advertisement up for one advertising interval.
                pdu_body = hci["addr"] + hci["data"]
                header = bytes([0x42, len(pdu_body)])  # ADV_NONCONN_IND, TxAdd random
                pdu = header + pdu_body
                frames.append((clock.now, bytes.fromhex("d6be898e") + pdu + ble_crc24(pdu)))
            hci["enabled"] = bool(data[0])

    ble._BleBase._acquire = ble_acquire
    ble._BleBase._send_hci_command = send_hci

    sys.argv = ["drone-spoofer"] + argv
    try:
        cli.main()
    except SystemExit:
        pass
    is_ble = "-t" in argv and argv[argv.index("-t") + 1] == "ble"
    pcap = Pcap(os.path.join(out_dir, name), 251 if is_ble else 127)
    for t, data in frames:
        pcap.write(t, data)
    pcap.close()
    print(f"{name}: {len(frames)} frames over {clock.now - START:.1f} s")
    sys.path.remove(repo)


def main():
    repo = os.path.abspath(sys.argv[1])
    out_dir = os.path.abspath(sys.argv[2])
    os.makedirs(out_dir, exist_ok=True)
    os.environ["TZ"] = "UTC"
    if hasattr(_real_time, "tzset"):
        _real_time.tzset()
    import logging

    logging.disable(logging.CRITICAL)
    only = sys.argv[3:] or None
    for name, argv in SCENARIOS:
        if only and name not in only:
            continue
        run(repo, out_dir, name, argv)


if __name__ == "__main__":
    main()
