# Spoof corpus

`tests/data/spoof` holds captures of what two public Remote ID spoofers
transmit, made without transmitting anything: each tool's own frame
building code runs on a host computer and its frames go to pcap files.

| File | Tool | Scenario | Link type |
|---|---|---|---|
| `cdc_wifi_random3.pcap` | cyber-defence-campus/droneRemoteIDSpoofer | `-r 3`: three random drones, Wi-Fi Beacon | 127 (radiotap) |
| `cdc_ble_legacy_random2.pcap` | same | `-t ble --ble-mode legacy -r 2` | 251 (BLE link layer) |
| `cdc_wifi_same_mac.pcap` | same | `scenarios/same_mac.json`: two drones sharing one MAC | 127 |
| `cdc_wifi_slow_forward.pcap` | same | `scenarios/slow_forward.json`: one slow waypoint drone | 127 |
| `jjshoots_esp8266_beacon_1drone.pcap` | jjshoots/RemoteIDSpoofer | ESP8266 build, one drone | 105 (802.11) |
| `jjshoots_esp8266_beacon_4drones.pcap` | same | ESP8266 build, four drones | 105 |

All runs start at 2026-11-17 12:00:00 UTC on a virtual clock and last 40
seconds.

## How they are made

`tools/spoof-corpus/regenerate.sh` clones both tools at pinned commits
(cyber-defence-campus `61fa634`, jjshoots `c79ab77`) and:

* **cyber-defence-campus** (Python): `cdc_harness.py` calls the tool's
  own CLI entry point with real arguments. Only the operating system edges
  are replaced: the raw Wi-Fi socket and the Bluetooth HCI socket record
  instead of send (an HCI "advertising enable" emits one advertising PDU),
  monitor mode setup is skipped, and `time` / `datetime` in its modules
  read a virtual clock driven by a cooperative scheduler that runs one
  thread at a time. `random` is seeded, so every run is identical.
* **jjshoots** (Arduino C++): the tool's `spoofer.cpp`, `id_open.cpp`,
  `id_open_beacon.cpp`, `utm.cpp`, `opendroneid.c`, `wifi.c` and
  `alt_unix_time.c` are compiled for the host as the ESP8266 build
  (`-DARDUINO_ARCH_ESP8266`) against a small Arduino shim
  (`tools/spoof-corpus/jjshoots/`). `harness.cpp` replaces the ESP8266
  platform file with the same bytes (capability, rates, Espressif element)
  and a pcap writer, and runs the sketch's `setup()` / `loop()` with fixed
  form inputs. `millis()` advances only through `delay()`, and the wall
  clock follows the sketch's `settimeofday()` call as on the board.
  `rand()` is the host C library's, so identifiers differ from a real
  board's but are made the same way.

Bluetooth 5 extended advertising and Wi-Fi NAN output of the
cyber-defence-campus tool are not in the corpus yet.

CI runs the script on Ubuntu and fails if the files change, so the corpus
stays reproducible from the pinned sources.

Use of the corpus: `tests/trust_corpus.rs` and `python/tests` check the
verdicts; `cargo run --example trust_report -- <capture>` prints them.
