# Drones in tar1090

[tar1090](https://github.com/wiedehopf/tar1090) draws whatever its
`aircraft.json` lists. `remoteid::aircraft_json` (Rust) and
`Tracker.aircraft_json()` (Python) write that file in the readsb schema
(`README-json.md` in wiedehopf/readsb), so any tar1090 install can show
Remote ID drones without changes to tar1090 or readsb.

## Fields

| Key | Value |
|---|---|
| `hex` | `~` and 6 hex digits from a hash of the transmitter address (`~` marks a non-ICAO address, as TIS-B uses) |
| `type` | `other` |
| `flight` | first 8 characters of the UAS ID |
| `r` | the full UAS ID (tar1090 shows it as the registration) |
| `category` | `B6` (unmanned aerial vehicle) |
| `lat`, `lon`, `seen_pos` | position and its age in seconds |
| `alt_geom`, `alt_baro` | feet; `alt_baro` is `"ground"` when the status says so |
| `gs`, `track`, `geom_rate` | knots, degrees, feet per minute |
| `emergency` | `general` when the status is Emergency |
| `messages`, `seen`, `rssi` | frames, age of the last frame, last RSSI |
| `rid` | Remote ID details: `transport`, `id`, `id_type`, `ua_type`, `operator_id`, `self_id`, `status`, `height_m`, `verdict`, `score`, `reasons`, `spoofer`, `auth` |

The operator (pilot) position from System messages is left out unless
`include_operator_position` is set; publish it only where that is lawful
and intended. Aircraft without a position, or not heard for 60 seconds,
are left out by default, as readsb does.

## Serving it

tar1090 reads `aircraft.json` from its data directory (by default
`/run/readsb`, set by `--write-json` in readsb). To show only drones, point
a second tar1090 instance at a directory of its own; to mix drones with
aircraft, merge the `aircraft` arrays of both files. Write the file to a
temporary name and rename it, so tar1090 never reads half a file:

```python
import os, time, remoteid

tracker = remoteid.Tracker()
# ... tracker.ingest(...) from your receiver loop ...
while True:
    tmp = "/run/remoteid/aircraft.json.tmp"
    with open(tmp, "w") as f:
        f.write(tracker.aircraft_json())
    os.replace(tmp, "/run/remoteid/aircraft.json")
    time.sleep(1)
```

The `rid.verdict` field lets a page or a script colour or filter drones
whose broadcast is suspicious or spoofed.
