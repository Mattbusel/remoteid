//! Per-transmitter aircraft tracking (needs the `std` feature).

use std::collections::HashMap;

use crate::{ble::BleRemoteId, wifi::WifiRemoteId, Frame, MessageType, UasData};

/// Who sent a frame. Receivers key aircraft by the radio address, because
/// that is the only thing every frame of one transmitter shares before its
/// Basic ID has been heard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transmitter {
    /// Bluetooth advertiser address.
    Ble([u8; 6]),
    /// Wi-Fi transmitter address.
    Wifi([u8; 6]),
    /// Anything else (for example a MAVLink system ID), chosen by the caller.
    Other(u64),
}

/// Counts derived from the one byte message counters.
///
/// Counters are tracked per message type for single messages (Bluetooth 4
/// keeps one counter per type) and once for packs. A repeat of the last
/// counter value counts as a duplicate; a jump forward of `n` counts `n - 1`
/// missed frames, and a late frame inside the reorder window takes one back.
/// Transmitters may legally repeat a counter when content is
/// unchanged, so `missed` is an estimate of lost frames, not an exact count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CounterStats {
    /// Frames accepted.
    pub received: u64,
    /// Frames whose counter repeated the previous one.
    pub duplicates: u64,
    /// Frames estimated lost from forward counter jumps.
    pub missed: u64,
    /// Times the counter went backwards by more than the reorder window
    /// (treated as a transmitter restart).
    pub resets: u64,
}

impl CounterStats {
    /// `missed / (received + missed)`, or 0 before any frame.
    pub fn loss_ratio(&self) -> f64 {
        let total = self.received + self.missed;
        if total == 0 {
            0.0
        } else {
            self.missed as f64 / total as f64
        }
    }
}

/// One tracked aircraft.
#[derive(Debug, Clone, Default)]
pub struct TrackedUas {
    /// Everything decoded so far.
    pub data: UasData,
    /// Timestamp (caller's clock) of the first frame.
    pub first_seen: u64,
    /// Timestamp of the latest frame.
    pub last_seen: u64,
    /// Counter statistics over all frames.
    pub stats: CounterStats,
    /// Frames that failed to decode.
    pub decode_errors: u64,
    last_counter: [Option<u8>; 8],
}

/// Tracker settings.
#[derive(Debug, Clone, Copy)]
pub struct TrackerConfig {
    /// Aircraft not heard for this long (in the caller's time unit) are
    /// removed by [`Tracker::expire`].
    pub timeout: u64,
    /// Counter steps backwards up to this size are taken as reordering, not
    /// as a restart.
    pub reorder_window: u8,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        // Assumes milliseconds: F3411 asks receivers to drop aircraft after
        // about 3 s without a Location; a 10 s default keeps slow
        // Bluetooth 4 transmitters that rotate message types.
        TrackerConfig {
            timeout: 10_000,
            reorder_window: 8,
        }
    }
}

/// Keeps one [`TrackedUas`] per transmitter.
///
/// Time is whatever monotonic unit the caller passes (milliseconds with the
/// default config); the tracker never reads a clock itself, so replaying a
/// capture gives the same result as live use.
///
/// ```
/// use remoteid::{ble, Tracker, Transmitter};
///
/// let adv = [0x1e, 0x16, 0xfa, 0xff, 0x0d, 0x01, 0x02, 0x12, b'A', b'B', b'C', b'D', b'1', b'X',
///            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// let mut t = Tracker::default();
/// let rid = ble::find_in_advertising_data(&adv).unwrap();
/// t.ingest_ble([1, 2, 3, 4, 5, 6], &rid, 1_000);
/// assert_eq!(t.len(), 1);
/// t.expire(20_000);
/// assert!(t.is_empty());
/// ```
#[derive(Debug, Clone, Default)]
pub struct Tracker {
    config: TrackerConfig,
    uas: HashMap<Transmitter, TrackedUas>,
}

impl Tracker {
    /// An empty tracker.
    pub fn new(config: TrackerConfig) -> Self {
        Tracker {
            config,
            uas: HashMap::new(),
        }
    }

    /// Records one decoded or undecodable payload.
    ///
    /// Returns the aircraft's entry. A frame that fails to decode still
    /// refreshes `last_seen` and counts as a decode error.
    pub fn ingest(
        &mut self,
        from: Transmitter,
        counter: u8,
        payload: &[u8],
        now: u64,
    ) -> &TrackedUas {
        let window = self.config.reorder_window;
        let entry = self.uas.entry(from).or_insert_with(|| TrackedUas {
            first_seen: now,
            ..TrackedUas::default()
        });
        entry.last_seen = entry.last_seen.max(now);
        let frame = match Frame::decode(payload) {
            Ok(f) => f,
            Err(_) => {
                entry.decode_errors += 1;
                return entry;
            }
        };
        let slot = match &frame {
            Frame::Pack(_) => 7,
            Frame::Message(m) => match m.message_type() {
                MessageType::Other(_) | MessageType::MessagePack => 7,
                t => u8::from(t).min(6) as usize,
            },
        };
        let stats = &mut entry.stats;
        let mut late = false;
        if let Some(prev) = entry.last_counter[slot] {
            let step = counter.wrapping_sub(prev);
            if step == 0 {
                stats.duplicates += 1;
            } else if step > 128 && (256 - step as u16) <= window as u16 {
                // A small step backwards is a late frame that an earlier
                // jump already counted as missed.
                late = true;
                stats.missed = stats.missed.saturating_sub(1);
            } else if step > 128 {
                stats.resets += 1;
            } else {
                stats.missed += step as u64 - 1;
            }
        }
        if !late {
            entry.last_counter[slot] = Some(counter);
        }
        stats.received += 1;
        entry.data.update_frame(&frame);
        entry
    }

    /// Records a Bluetooth frame.
    pub fn ingest_ble(&mut self, address: [u8; 6], rid: &BleRemoteId<'_>, now: u64) -> &TrackedUas {
        self.ingest(Transmitter::Ble(address), rid.counter, rid.payload, now)
    }

    /// Records a Wi-Fi frame, keyed by its source address.
    pub fn ingest_wifi(&mut self, rid: &WifiRemoteId<'_>, now: u64) -> &TrackedUas {
        self.ingest(Transmitter::Wifi(rid.source), rid.counter, rid.payload, now)
    }

    /// Removes aircraft not heard since `now - timeout`. Returns how many.
    pub fn expire(&mut self, now: u64) -> usize {
        let before = self.uas.len();
        let timeout = self.config.timeout;
        self.uas
            .retain(|_, u| now.saturating_sub(u.last_seen) <= timeout);
        before - self.uas.len()
    }

    /// The entry for one transmitter.
    pub fn get(&self, from: &Transmitter) -> Option<&TrackedUas> {
        self.uas.get(from)
    }

    /// All tracked aircraft.
    pub fn iter(&self) -> impl Iterator<Item = (&Transmitter, &TrackedUas)> {
        self.uas.iter()
    }

    /// Number of tracked aircraft.
    pub fn len(&self) -> usize {
        self.uas.len()
    }

    /// `true` when nothing is tracked.
    pub fn is_empty(&self) -> bool {
        self.uas.is_empty()
    }
}
