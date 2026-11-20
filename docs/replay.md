# remoteid-replay: the spoof gate for Remote ID receivers

A Remote ID receiver that decodes fields and draws them on a map believes
every broadcast. `remoteid-replay` checks that claim against bytes: it
replays captures of two public spoofing tools (12 fake transmitters, 10 on
Wi-Fi and 2 on Bluetooth) and of a real transmitter through your receiver,
and exits 1 when your receiver shows a spoofed transmitter as real.

```sh
cargo install remoteid --features cli
remoteid-replay run --receiver "python my_receiver.py --pcap {capture}"
```

## The receiver contract

`--receiver` is a shell command. It runs once per capture, with
`{capture}` replaced by the capture's path (appended when absent), and
prints one JSON object per transmitter it shows, or per detection; several
lines for one transmitter are merged.

```json
{"mac": "26:55:b3:b1:48:81", "uas_id": "Spoofed_Serial_90575", "verdict": "spoofed"}
```

| Field | Keys read |
|---|---|
| Address | `addr`, `address`, `mac`, `sender_id`, `src`, `source_address` (any separator; Bluetooth in either byte order) |
| UAS ID | `id`, `uas_id`, `basic_id`, `serial`, `serial_number`, `drone_id`, `uav_id` |
| Verdict | `verdict`, `trust`, `status` (text containing `spoofed`, `suspicious`, `flagged`, `fake`, `alert`, `rejected` or `untrusted` is a warning), or `spoofed`, `suspicious`, `flagged` (booleans) |

**A line without a verdict counts as accepted.** That is what a receiver
with no spoof checks puts on its map. Lines that are not JSON objects
(logs, banners) are ignored. Reports are matched to the capture's
transmitters by address first, then by any UAS ID the transmitter sent; a
report that matches nothing is a phantom.

A receiver that exits non-zero on a capture (a crash) fails the run, and
so does a receiver that shows nothing at all: it proved nothing.

## Commands

| Command | Does |
|---|---|
| `run [--receiver CMD]` | Replay and score. Without `--receiver`, remoteid is the receiver |
| `score --reports FILE` | Score saved output; each line names its `capture` |
| `verdicts CAPTURE...` | remoteid's verdicts as JSON lines, for pcap, pcapng or RIDF |
| `frames [--ridf OUT] CAPTURE...` | The Remote ID frames as JSON lines (hex) or one RIDF file, for receivers that do not read pcap |
| `corpus DIR` | Write the captures and `manifest.json` (truth, source, transmitters and their UAS IDs) |

Options: `--link wifi|ble|all`, `--spoofed FILE` and `--legit FILE` (add
your own labelled captures, for example field recordings of your fleet to
measure false alarms), `--format text|markdown|json`, `--details`,
`--allow-false-alarms`, `--fail-on-missed`, `--fail-on-phantom`.

Exit status: 0 pass, 1 the gate failed, 2 usage or I/O error.

## GitHub Action

```yaml
- uses: Mattbusel/remoteid@v0.3.0
  with:
    receiver: python my_receiver.py --pcap {capture}
    link: wifi
```

The job fails when a spoofed transmitter is accepted. The table goes to the
job summary and the JSON result to the `result` output.

## What the corpus is

See [spoof-corpus.md](spoof-corpus.md): the spoofers' own frame building
code, run on a host with no radio, at pinned commits, regenerated and
diffed in CI. The real captures are the Open Drone ID sample captures
(Apache-2.0). Results for eight open-source receivers are in
[receivers.md](receivers.md).

## Library

The same pieces are in the crate with the `std` feature:
[`capture`](https://docs.rs/remoteid/latest/remoteid/capture/) reads pcap,
pcapng and RIDF into frames and replays them through a `Tracker`;
[`replay`](https://docs.rs/remoteid/latest/remoteid/replay/) matches
receiver reports to transmitters and applies the gate.
