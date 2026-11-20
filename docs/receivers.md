# Open-source Remote ID receivers against the spoof corpus

Measured on 2026-11-20 with `remoteid-replay run --link wifi` (remoteid
0.3.0). Each receiver ran its own decode path on the Wi-Fi captures of the
bundled corpus: 10 spoofed transmitters made by the source code of two
public spoofers (cyber-defence-campus/droneRemoteIDSpoofer and
jjshoots/RemoteIDSpoofer, see [spoof-corpus.md](spoof-corpus.md)) and 2
captures of a real transmitter (the Open Drone ID sample captures, Wi-Fi
Beacon and Wi-Fi NAN). The adapters that feed each receiver are in
[`tools/receivers`](../tools/receivers), with the exact functions they call.

**Accepted** means the receiver put the spoofed transmitter in front of
its user as a drone with no warning. **Not shown** means it never displayed
that transmitter at all (a decode gap, not a defense).

| Receiver | Stars | Commit | Spoofed: flagged | Spoofed: accepted as real | Spoofed: not shown | Real: shown | Notes |
|---|---|---|---|---|---|---|---|
| **remoteid 0.3.0** (built in) | | | **10** | **0** | 0 | 2 / 2 | 12 / 12 with the Bluetooth capture; 10 / 10 with tool fingerprints off |
| [smittix/intercept](https://github.com/smittix/intercept) | 2,479 | `d1a655e` | 0 | 0 | 10 | 0 / 2 | Decodes no real frame: `utils/drone/remote_id.py:43` takes the message type from the low nibble (the protocol version). Its correlator marks every Remote ID contact `compliant=True`, risk `low` (`utils/drone/correlator.py:26`, `:58`) |
| [cyber-defence-campus/RemoteIDReceiver](https://github.com/cyber-defence-campus/RemoteIDReceiver) | 320 | `8389e23` | 0 | 7 | 3 | 2 / 2 | Has a spoof check, `spoofing_detection.py:6`: operator more than 15 km from the drone. It said `spoofed=false` for all 7. The 3 not shown sent no Location message |
| [colonelpanichacks/drone-mesh-mapper](https://github.com/colonelpanichacks/drone-mesh-mapper) (`remoteid-mesh` firmware) | 246 | `79f50b2` | 0 | 10 | 0 | 2 / 2 | ESP32 firmware built for the host; its USB serial JSON is what `mesh-mapper.py` maps |
| [arall/sigint](https://github.com/arall/sigint) | 195 | `174003a` | 0 | 10 | 0 | 2 / 2 | |
| [colonelpanichacks/Sky-Spy](https://github.com/colonelpanichacks/Sky-Spy) | 185 | `3e092cb` | 0 | 10 | 0 | 1 / 2 | **Crashes on the first Wi-Fi NAN Remote ID frame**: `src/main.cpp:233` passes `nullptr` as the MAC buffer and `src/wifi.c:576` copies into it. On the board that is a store to address 0, a panic and a reboot |
| [bkerler/DroneID](https://github.com/bkerler/DroneID) | 113 | `325a63b` | 0 | 10 | 0 | 2 / 2 | `wifi_receiver.py` and `zmq_decoder.py` in one process |
| [ifnull/dump3411](https://github.com/ifnull/dump3411) | 34 | `c558b33` | 0 | 5 | 5 | 1 / 2 | The tracker is keyed by Basic ID, so transmitters that send none (the jjshoots spoofer, the NAN sample) never reach its feed |
| [dougborg/AirHound](https://github.com/dougborg/AirHound) | 14 | `0d9da0e` | 0 | 10 | 0 | 2 / 2 | Decodes with remoteid 0.1 (no trust verdicts yet) |

Across the eight receivers: **0 of the 10 spoofed transmitters flagged by
any of them; 62 of 80 receiver and transmitter pairs shown as real
drones.** The one receiver with a spoof check tests a rule the spoofers
already satisfy (they put the operator next to the drone).

Not replayed: opendroneid/receiver-android (an Android app; its parser
needs the Android runtime), alphafox02/droneid-go (ships binaries, no
source), alphafox02/DragonSync (reads already decoded JSON from a
decoder, it has no frame decoder of its own).

## Reproduce

Each row is one command. With a checkout of the receiver at the commit
above in `SRC`:

```sh
cargo install remoteid --version 0.3.0 --features cli
pip install scapy==2.6.1 geopy pydantic sqlalchemy pyzmq pyserial pwinput pytz
remoteid-replay run --link wifi --details --receiver "python -I tools/receivers/remoteidreceiver.py $SRC {capture}"
remoteid-replay run --link wifi --details --receiver "python -I tools/receivers/sigint.py $SRC {capture}"
remoteid-replay run --link wifi --details --receiver "python -I tools/receivers/intercept.py $SRC {capture}"
remoteid-replay run --link wifi --details --receiver "python -I tools/receivers/droneid.py $SRC {capture}"
remoteid-replay run --link wifi --details --receiver "python -I tools/receivers/dump3411.py $SRC {capture}"
# ESP32 firmware (Linux, gcc/g++): build the firmware's own sources for the host
tools/receivers/esp32/build.sh $SRC/src glue_skyspy.cpp /tmp/skyspy
tools/receivers/esp32/build.sh $SRC/remoteid-mesh/src glue_meshmapper.cpp /tmp/meshmapper
remoteid-replay run --link wifi --details --receiver "python tools/receivers/esp32/run.py /tmp/skyspy {capture}"
# AirHound: set the path in tools/receivers/airhound/Cargo.toml to $SRC
cargo build --release --manifest-path tools/receivers/airhound/Cargo.toml
remoteid-replay run --link wifi --details --receiver "tools/receivers/airhound/target/release/airhound-replay {capture}"
```

Python receivers run with `-I` so nothing next to the capture is imported.
Results were measured on Windows 11 (Python 3.12) and, for the firmware
builds, Ubuntu 24.04 under WSL.
