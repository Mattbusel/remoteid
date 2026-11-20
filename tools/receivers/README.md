# Receiver adapters

Each adapter runs one open-source Remote ID receiver's own decode path on a
capture and prints what that receiver would show, one JSON line per
transmitter, for `remoteid-replay run --receiver`. Nothing is
reimplemented: the adapters import the receiver's modules, or (for ESP32
firmware) compile its sources for the host, and only replace the radio,
the database or the serial port. The docstring at the top of each file
names the exact functions it calls.

| Adapter | Receiver |
|---|---|
| `remoteidreceiver.py` | cyber-defence-campus/RemoteIDReceiver |
| `sigint.py` | arall/sigint |
| `intercept.py` | smittix/intercept |
| `droneid.py` | bkerler/DroneID |
| `dump3411.py` | ifnull/dump3411 |
| `esp32/` | ESP32 Arduino scanners (colonelpanichacks Sky-Spy, drone-mesh-mapper): `build.sh` builds `main.cpp`, `wifi.c` and `opendroneid.c` against `shim/`, `harness.cpp` feeds the promiscuous callback, `run.py` runs it (under WSL on Windows) |
| `airhound/` | dougborg/AirHound (`scanner::try_parse_odid_wifi` then `odid::parse_odid_service_info`) |

Results and the commands that produced them: [docs/receivers.md](../../docs/receivers.md).
