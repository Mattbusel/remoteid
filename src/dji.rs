//! DJI DroneID: the telemetry DJI aircraft broadcast besides (and before)
//! ASTM Remote ID.
//!
//! DJI aircraft send their own "DroneID" frames on two radios:
//!
//! * **OcuSync** (Mini 2, Mavic Air 2, Mavic 3, Air 2S and most models since
//!   2019) sends a 91 byte payload in a dedicated burst on the video link.
//!   Turning the RF burst into those 91 bytes needs an SDR demodulator (for
//!   example the NDSS 2023 receiver from Ruhr University Bochum, or the
//!   AntSDR DroneID firmware); this module takes over from there:
//!   [`FlightInfo::decode`] checks the CRC and decodes the fields, and
//!   [`antsdr`] reads the decoded reports an AntSDR streams over TCP.
//! * **Wi-Fi** models (Spark, Mavic Air, Mavic Mini and other enhanced
//!   Wi-Fi aircraft) put the same record in a beacon vendor element with
//!   OUI `26:37:12`: [`find_in_elements`] / [`parse_vendor_element`].
//!
//! Neither format is published by DJI. The layout here follows the public
//! reverse engineering: the NDSS 2023 paper "Drone Security and the
//! Mysterious Case of DJI's DroneID" (Schiller et al.), and the Wi-Fi parser
//! in Kismet (format decoded by Freek van Tienen and Jan Dumon). The test
//! suite checks the decoder against payloads demodulated from the paper's
//! published Mini 2 and Mavic Air 2 captures, CRC included.
//!
//! What is certain and what is not:
//!
//! * Serial number, positions (aircraft, home point, pilot app), GPS time,
//!   product type and the CRC are confirmed by the captures.
//! * Altitude, height and velocity units are not established in public
//!   sources, so they are kept as the raw integers. [`FlightInfo::altitude_m`]
//!   and [`FlightInfo::height_m`] apply the feet interpretation of the NDSS
//!   reference receiver and say so.
//! * The `state_info` bit meanings differ between sources, so the word is
//!   kept raw.
//! * Newer firmware can encrypt the payload; such frames still pass the CRC
//!   but their serial is not text, and [`FlightInfo::serial_str`] returns
//!   `None`.
//!
//! DroneID positions feed the rest of the crate through
//! [`FlightInfo::messages`], which builds the equivalent Remote ID Basic
//! ID, Location and System messages for [`UasData`](crate::UasData) and the
//! [`Tracker`](crate::Tracker).

use crate::wifi::{elements, ELEMENT_VENDOR};
use crate::{
    BasicId, Error, HeightType, IdType, Location, Message, OperatorLocationType, Status, System,
    UaType,
};

/// Length of the decoded OcuSync DroneID payload, CRC included.
pub const PAYLOAD_LEN: usize = 91;
/// OUI of the DJI DroneID Wi-Fi vendor element.
pub const WIFI_OUI: [u8; 3] = [0x26, 0x37, 0x12];
/// Record type of flight telemetry (position, home point, pilot position).
pub const SUBCOMMAND_FLIGHT_INFO: u8 = 0x10;
/// Record type of the user entered flight purpose (Wi-Fi only).
pub const SUBCOMMAND_FLIGHT_PURPOSE: u8 = 0x11;

/// Initial value of the payload CRC (CRC-16, reflected polynomial 0x1021).
pub const CRC_INIT: u16 = 0x3692;

/// CRC-16 of the OcuSync payload: polynomial 0x1021 bit reflected, initial
/// value [`CRC_INIT`], no final XOR. It covers bytes 0 to 88; bytes 89 and
/// 90 carry it little endian.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = CRC_INIT;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// Product type codes as listed by the NDSS 2023 reference receiver.
const PRODUCTS: &[(u8, &str)] = &[
    (1, "Inspire 1"),
    (2, "Phantom 3 Series"),
    (3, "Phantom 3 Series"),
    (4, "Phantom 3 Std"),
    (5, "M100"),
    (6, "ACEONE"),
    (7, "WKM"),
    (8, "NAZA"),
    (9, "A2"),
    (10, "A3"),
    (11, "Phantom 4"),
    (12, "MG1"),
    (14, "M600"),
    (15, "Phantom 3 4k"),
    (16, "Mavic Pro"),
    (17, "Inspire 2"),
    (18, "Phantom 4 Pro"),
    (20, "N2"),
    (21, "Spark"),
    (23, "M600 Pro"),
    (24, "Mavic Air"),
    (25, "M200"),
    (26, "Phantom 4 Series"),
    (27, "Phantom 4 Adv"),
    (28, "M210"),
    (30, "M210RTK"),
    (31, "A3_AG"),
    (32, "MG2"),
    (34, "MG1A"),
    (35, "Phantom 4 RTK"),
    (36, "Phantom 4 Pro V2.0"),
    (38, "MG1P"),
    (40, "MG1P-RTK"),
    (41, "Mavic 2"),
    (44, "M200 V2 Series"),
    (51, "Mavic 2 Enterprise"),
    (53, "Mavic Mini"),
    (58, "Mavic Air 2"),
    (59, "P4M"),
    (60, "M300 RTK"),
    (61, "DJI FPV"),
    (63, "Mini 2"),
    (64, "AGRAS T10"),
    (65, "AGRAS T30"),
    (66, "Air 2S"),
    (67, "M30"),
    (68, "DJI Mavic 3"),
    (69, "Mavic 2 Enterprise Advanced"),
    (70, "Mini SE"),
];

/// Model name for a DroneID product type code, when the code is known.
pub fn product_name(code: u8) -> Option<&'static str> {
    PRODUCTS.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}

/// Converts a DroneID coordinate (radians times 1e7) to degrees.
pub fn raw_to_degrees(raw: i32) -> f64 {
    (raw as f64 / 1e7).to_degrees()
}

fn pair(lat_raw: i32, lon_raw: i32) -> Option<(f64, f64)> {
    if lat_raw == 0 && lon_raw == 0 {
        None
    } else {
        Some((raw_to_degrees(lat_raw), raw_to_degrees(lon_raw)))
    }
}

fn text(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s = &bytes[..end];
    if !s.is_empty() && s.iter().all(|b| (0x20..0x7f).contains(b)) {
        core::str::from_utf8(s).ok()
    } else {
        None
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&self.b[self.at..self.at + N]);
        self.at += N;
        out
    }
    fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take())
    }
    fn i16(&mut self) -> i16 {
        i16::from_le_bytes(self.take())
    }
    fn i32(&mut self) -> i32 {
        i32::from_le_bytes(self.take())
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take())
    }
}

/// Bytes of a version 2 flight record from the version byte to the end of
/// the UUID (the OcuSync payload adds a length byte, the record type and the
/// CRC around it).
const RECORD_V2_LEN: usize = 87;
/// Bytes of a version 1 flight record (older Wi-Fi firmware).
const RECORD_V1_LEN: usize = 75;

/// One DroneID flight telemetry record (record type 0x10).
///
/// Coordinates are kept in the transmitted form (radians times 1e7); the
/// accessors return degrees and `None` for the 0, 0 "not known" value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlightInfo {
    /// Record version: 2 on OcuSync and current Wi-Fi firmware, 1 on older
    /// Wi-Fi firmware.
    pub version: u8,
    /// Sequence number, incremented per frame.
    pub sequence: u16,
    /// State flags. Public sources disagree on the bit meanings, so the word
    /// is kept raw.
    pub state_info: u16,
    /// Serial number, NUL padded ASCII (not text when the payload is
    /// encrypted).
    pub serial: [u8; 16],
    /// Aircraft longitude, radians times 1e7.
    pub longitude_raw: i32,
    /// Aircraft latitude, radians times 1e7.
    pub latitude_raw: i32,
    /// Altitude as transmitted (unit not established; see [`FlightInfo::altitude_m`]).
    pub altitude_raw: i16,
    /// Height as transmitted (unit not established; see [`FlightInfo::height_m`]).
    pub height_raw: i16,
    /// Velocity north as transmitted.
    pub v_north: i16,
    /// Velocity east as transmitted.
    pub v_east: i16,
    /// Velocity up as transmitted.
    pub v_up: i16,
    /// Pitch and roll in hundredths of a degree (version 1 records only).
    pub pitch_roll_raw: Option<(i16, i16)>,
    /// Yaw in hundredths of a degree.
    pub yaw_raw: i16,
    /// GPS time in milliseconds since the Unix epoch (version 2 only).
    pub gps_time_ms: Option<u64>,
    /// Pilot (phone app) latitude, radians times 1e7 (version 2 only).
    pub app_latitude_raw: Option<i32>,
    /// Pilot (phone app) longitude, radians times 1e7 (version 2 only).
    pub app_longitude_raw: Option<i32>,
    /// Home point longitude, radians times 1e7.
    pub home_longitude_raw: i32,
    /// Home point latitude, radians times 1e7.
    pub home_latitude_raw: i32,
    /// Product type code; see [`product_name`].
    pub product_type: u8,
    /// Length of the UUID in `uuid` as transmitted.
    pub uuid_len: u8,
    /// Flight UUID, NUL padded.
    pub uuid: [u8; 20],
}

impl FlightInfo {
    /// Decodes a 91 byte OcuSync DroneID payload and checks its CRC.
    ///
    /// Longer input is accepted (demodulators often hand over whole frames);
    /// only the first [`PAYLOAD_LEN`] bytes are read.
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() < PAYLOAD_LEN {
            return Err(Error::TooShort {
                need: PAYLOAD_LEN,
                got: payload.len(),
            });
        }
        let computed = crc16(&payload[..PAYLOAD_LEN - 2]);
        let found = u16::from_le_bytes([payload[PAYLOAD_LEN - 2], payload[PAYLOAD_LEN - 1]]);
        if computed != found {
            return Err(Error::ChecksumMismatch { computed, found });
        }
        Self::decode_unchecked(payload)
    }

    /// Decodes an OcuSync DroneID payload without checking the CRC, for
    /// frames whose CRC the caller already checked or wants to inspect
    /// anyway. Needs the first 89 bytes.
    pub fn decode_unchecked(payload: &[u8]) -> Result<Self, Error> {
        let need = 2 + RECORD_V2_LEN;
        if payload.len() < need {
            return Err(Error::TooShort {
                need,
                got: payload.len(),
            });
        }
        if payload[1] != SUBCOMMAND_FLIGHT_INFO {
            return Err(Error::NotRemoteId);
        }
        Self::decode_record(&payload[2..])
    }

    /// Decodes a flight record starting at its version byte (the layout
    /// shared by the OcuSync payload and the Wi-Fi element). Version 1
    /// records use the older Wi-Fi layout; any other version is read with
    /// the version 2 layout.
    pub fn decode_record(record: &[u8]) -> Result<Self, Error> {
        let version = *record.first().ok_or(Error::TooShort { need: 1, got: 0 })?;
        let need = if version == 1 {
            RECORD_V1_LEN
        } else {
            RECORD_V2_LEN
        };
        if record.len() < need {
            return Err(Error::TooShort {
                need,
                got: record.len(),
            });
        }
        let mut r = Reader { b: record, at: 1 };
        let sequence = r.u16();
        let state_info = r.u16();
        let serial = r.take::<16>();
        let longitude_raw = r.i32();
        let latitude_raw = r.i32();
        let altitude_raw = r.i16();
        let height_raw = r.i16();
        let v_north = r.i16();
        let v_east = r.i16();
        let v_up = r.i16();
        let (pitch_roll_raw, yaw_raw, gps_time_ms, app_latitude_raw, app_longitude_raw) =
            if version == 1 {
                let pitch = r.i16();
                let roll = r.i16();
                (Some((pitch, roll)), r.i16(), None, None, None)
            } else {
                let yaw = r.i16();
                let t = r.u64();
                let alat = r.i32();
                let alon = r.i32();
                (None, yaw, Some(t), Some(alat), Some(alon))
            };
        let home_longitude_raw = r.i32();
        let home_latitude_raw = r.i32();
        let product_type = r.u8();
        let uuid_len = r.u8();
        let uuid = r.take::<20>();
        Ok(FlightInfo {
            version,
            sequence,
            state_info,
            serial,
            longitude_raw,
            latitude_raw,
            altitude_raw,
            height_raw,
            v_north,
            v_east,
            v_up,
            pitch_roll_raw,
            yaw_raw,
            gps_time_ms,
            app_latitude_raw,
            app_longitude_raw,
            home_longitude_raw,
            home_latitude_raw,
            product_type,
            uuid_len,
            uuid,
        })
    }

    /// The serial number, or `None` when it is empty or not printable ASCII
    /// (an encrypted payload).
    pub fn serial_str(&self) -> Option<&str> {
        text(&self.serial)
    }

    /// The flight UUID as text, cut to `uuid_len`, or `None` when empty.
    pub fn uuid_str(&self) -> Option<&str> {
        let n = (self.uuid_len as usize).min(self.uuid.len());
        text(&self.uuid[..n])
    }

    /// Aircraft position (latitude, longitude) in degrees; `None` before the
    /// aircraft has a GPS fix.
    pub fn position(&self) -> Option<(f64, f64)> {
        pair(self.latitude_raw, self.longitude_raw)
    }

    /// Home point (latitude, longitude) in degrees.
    pub fn home_position(&self) -> Option<(f64, f64)> {
        pair(self.home_latitude_raw, self.home_longitude_raw)
    }

    /// Pilot position (latitude, longitude) in degrees, from the phone
    /// running the DJI app. Version 2 records only.
    pub fn pilot_position(&self) -> Option<(f64, f64)> {
        pair(self.app_latitude_raw?, self.app_longitude_raw?)
    }

    /// Yaw (heading of the airframe) in degrees.
    pub fn yaw_deg(&self) -> f32 {
        self.yaw_raw as f32 / 100.0
    }

    /// A stable key for [`Transmitter::Other`](crate::Transmitter::Other):
    /// FNV-1a of the serial bytes. OcuSync frames carry no radio address,
    /// so the serial is what ties one aircraft's frames together.
    pub fn key(&self) -> u64 {
        self.serial.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
            (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }

    /// Model name from the product type code.
    pub fn product_name(&self) -> Option<&'static str> {
        product_name(self.product_type)
    }

    /// Altitude in meters, reading the raw value as feet the way the NDSS
    /// 2023 reference receiver does. DJI has not published the unit.
    pub fn altitude_m(&self) -> f32 {
        self.altitude_raw as f32 * 0.3048
    }

    /// Height in meters, reading the raw value as feet the way the NDSS
    /// 2023 reference receiver does. DJI has not published the unit.
    pub fn height_m(&self) -> f32 {
        self.height_raw as f32 * 0.3048
    }

    /// The equivalent Remote ID messages, so DroneID aircraft go through
    /// [`UasData`](crate::UasData), the [`Tracker`](crate::Tracker) and
    /// `aircraft.json` like any other:
    ///
    /// * Basic ID (serial number, multirotor) when the serial is text,
    /// * Location with the aircraft position and, from the GPS time, the
    ///   timestamp; heights and speeds are left unset because their units
    ///   are not established,
    /// * System with the pilot position (live GNSS of the phone) and the
    ///   timestamp.
    ///
    /// Messages without data (no serial, no fix, no pilot position) are
    /// skipped.
    pub fn messages(&self) -> impl Iterator<Item = Message> {
        let basic = self.serial_str().and_then(|s| {
            BasicId::new(IdType::SerialNumber, UaType::HelicopterOrMultirotor, s)
                .ok()
                .map(Message::BasicId)
        });
        let location = self.position().map(|(lat, lon)| {
            Message::Location(Location {
                status: Status::Undeclared,
                height_type: HeightType::AboveTakeoff,
                latitude: lat,
                longitude: lon,
                timestamp: self
                    .gps_time_ms
                    .map(|t| ((t % 3_600_000) / 100) as f32 / 10.0),
                ..Location::default()
            })
        });
        let system = self.pilot_position().map(|(lat, lon)| {
            Message::System(System {
                operator_location_type: OperatorLocationType::LiveGnss,
                operator_latitude: lat,
                operator_longitude: lon,
                timestamp: self
                    .gps_time_ms
                    .map(|t| (t / 1000).saturating_sub(SYSTEM_EPOCH_UNIX))
                    .and_then(|s| u32::try_from(s).ok())
                    .unwrap_or(0),
                ..System::default()
            })
        });
        basic.into_iter().chain(location).chain(system)
    }
}

/// 2019-01-01 00:00:00 UTC as a Unix time: the epoch of the System message
/// timestamp.
const SYSTEM_EPOCH_UNIX: u64 = 1_546_300_800;

/// The user entered flight purpose record (record type 0x11, Wi-Fi only).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlightPurpose<'a> {
    /// Serial number, NUL padded.
    pub serial: [u8; 16],
    /// Drone ID entered by the user, cut to its length byte.
    pub drone_id: &'a [u8],
    /// Flight purpose entered by the user, cut to its length byte. DJI
    /// firmware is known to send it truncated, so it may be shorter.
    pub purpose: &'a [u8],
}

impl<'a> FlightPurpose<'a> {
    /// Decodes a flight purpose record (after the record type byte).
    pub fn decode(record: &'a [u8]) -> Result<Self, Error> {
        let need = 16 + 1 + 10 + 1;
        if record.len() < need {
            return Err(Error::TooShort {
                need,
                got: record.len(),
            });
        }
        let mut serial = [0u8; 16];
        serial.copy_from_slice(&record[..16]);
        let id_len = (record[16] as usize).min(10);
        let drone_id = &record[17..17 + id_len];
        let purpose_len = record[27] as usize;
        let rest = &record[28..];
        let purpose = &rest[..purpose_len.min(rest.len())];
        Ok(FlightPurpose {
            serial,
            drone_id,
            purpose,
        })
    }

    /// The serial number as text.
    pub fn serial_str(&self) -> Option<&str> {
        text(&self.serial)
    }

    /// The drone ID as text.
    pub fn drone_id_str(&self) -> Option<&str> {
        text(self.drone_id)
    }

    /// The flight purpose as text.
    pub fn purpose_str(&self) -> Option<&str> {
        text(self.purpose)
    }
}

/// A DroneID record from a Wi-Fi beacon.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum WifiDroneId<'a> {
    /// Flight telemetry (record type 0x10).
    FlightInfo(FlightInfo),
    /// User entered flight purpose (record type 0x11).
    FlightPurpose(FlightPurpose<'a>),
    /// A record type this crate does not decode, kept raw.
    Other {
        /// Record type byte.
        subcommand: u8,
        /// Record bytes after the type.
        record: &'a [u8],
    },
}

/// Parses the body of a vendor specific element (element ID 221) that may
/// carry DroneID: OUI `26:37:12`, then a vendor type, two bytes not yet
/// understood, the record type and the record.
pub fn parse_vendor_element(info: &[u8]) -> Result<WifiDroneId<'_>, Error> {
    if info.len() < 3 || info[..3] != WIFI_OUI {
        return Err(Error::NotRemoteId);
    }
    if info.len() < 7 {
        return Err(Error::TooShort {
            need: 7,
            got: info.len(),
        });
    }
    let subcommand = info[6];
    let record = &info[7..];
    match subcommand {
        SUBCOMMAND_FLIGHT_INFO => FlightInfo::decode_record(record).map(WifiDroneId::FlightInfo),
        SUBCOMMAND_FLIGHT_PURPOSE => FlightPurpose::decode(record).map(WifiDroneId::FlightPurpose),
        _ => Ok(WifiDroneId::Other { subcommand, record }),
    }
}

/// Finds the first DroneID element in a run of 802.11 information elements
/// (for example the tagged parameters of a beacon). Elements that carry the
/// DJI OUI but do not decode are skipped.
pub fn find_in_elements(ies: &[u8]) -> Option<WifiDroneId<'_>> {
    elements(ies)
        .filter(|(id, _)| *id == ELEMENT_VENDOR)
        .find_map(|(_, body)| parse_vendor_element(body).ok())
}

/// Decoded reports from an AntSDR running DJI DroneID firmware.
///
/// The AntSDR demodulates OcuSync DroneID on board and streams one framed
/// report per DroneID frame over TCP (the format Kismet's
/// `kismet_cap_antsdr_droneid` reads). All numbers are little endian.
pub mod antsdr {
    use crate::Error;

    /// Bytes of the frame header: a 16 bit header word, the packet type and
    /// a 16 bit body length.
    pub const HEADER_LEN: usize = 5;
    /// Packet type of a DroneID report.
    pub const PACKET_DRONEID: u8 = 0x01;
    /// Bytes of a DroneID report body.
    pub const REPORT_LEN: usize = 64 + 64 + 1 + 12 * 8 + 4;

    /// One frame from the TCP stream.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Frame<'a> {
        /// The 16 bit header word as sent.
        pub header: u16,
        /// Packet type ([`PACKET_DRONEID`] for reports).
        pub packet_type: u8,
        /// The body.
        pub body: &'a [u8],
    }

    /// Splits the next frame off a TCP receive buffer. Returns the frame and
    /// the bytes it used, or `TooShort` when the buffer does not hold a whole
    /// frame yet (read more and call again).
    pub fn next_frame(buf: &[u8]) -> Result<(Frame<'_>, usize), Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::TooShort {
                need: HEADER_LEN,
                got: buf.len(),
            });
        }
        let len = u16::from_le_bytes([buf[3], buf[4]]) as usize;
        let total = HEADER_LEN + len;
        if buf.len() < total {
            return Err(Error::TooShort {
                need: total,
                got: buf.len(),
            });
        }
        Ok((
            Frame {
                header: u16::from_le_bytes([buf[0], buf[1]]),
                packet_type: buf[2],
                body: &buf[HEADER_LEN..total],
            },
            total,
        ))
    }

    /// A DroneID report as the AntSDR sends it: positions in degrees,
    /// already converted on the device.
    #[derive(Debug, Clone, PartialEq)]
    pub struct Report {
        /// Serial number, NUL padded.
        pub serial: [u8; 64],
        /// Model name, NUL padded.
        pub device_type: [u8; 64],
        /// Product type code (see [`super::product_name`]).
        pub device_type_code: u8,
        /// Pilot latitude in degrees.
        pub app_latitude: f64,
        /// Pilot longitude in degrees.
        pub app_longitude: f64,
        /// Aircraft latitude in degrees.
        pub drone_latitude: f64,
        /// Aircraft longitude in degrees.
        pub drone_longitude: f64,
        /// Height as reported.
        pub height: f64,
        /// Altitude as reported.
        pub altitude: f64,
        /// Home latitude in degrees.
        pub home_latitude: f64,
        /// Home longitude in degrees.
        pub home_longitude: f64,
        /// Frequency the frame was received on, as reported.
        pub frequency: f64,
        /// Velocity east as reported.
        pub speed_east: f64,
        /// Velocity north as reported.
        pub speed_north: f64,
        /// Velocity up as reported.
        pub speed_up: f64,
        /// Received signal strength as reported.
        pub rssi: u32,
    }

    impl Report {
        /// Decodes a report body (packet type [`PACKET_DRONEID`]).
        pub fn decode(body: &[u8]) -> Result<Self, Error> {
            if body.len() < REPORT_LEN {
                return Err(Error::TooShort {
                    need: REPORT_LEN,
                    got: body.len(),
                });
            }
            let mut serial = [0u8; 64];
            serial.copy_from_slice(&body[..64]);
            let mut device_type = [0u8; 64];
            device_type.copy_from_slice(&body[64..128]);
            let f = |i: usize| {
                let at = 129 + i * 8;
                let mut b = [0u8; 8];
                b.copy_from_slice(&body[at..at + 8]);
                f64::from_le_bytes(b)
            };
            let at = 129 + 12 * 8;
            Ok(Report {
                serial,
                device_type,
                device_type_code: body[128],
                app_latitude: f(0),
                app_longitude: f(1),
                drone_latitude: f(2),
                drone_longitude: f(3),
                height: f(4),
                altitude: f(5),
                home_latitude: f(6),
                home_longitude: f(7),
                frequency: f(8),
                speed_east: f(9),
                speed_north: f(10),
                speed_up: f(11),
                rssi: u32::from_le_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]),
            })
        }

        /// Decodes a frame if it is a DroneID report; `NotRemoteId` for
        /// other packet types.
        pub fn from_frame(frame: &Frame<'_>) -> Result<Self, Error> {
            if frame.packet_type != PACKET_DRONEID {
                return Err(Error::NotRemoteId);
            }
            Self::decode(frame.body)
        }

        /// The serial number as text (`None` for encrypted or empty serials).
        pub fn serial_str(&self) -> Option<&str> {
            super::text(&self.serial)
        }

        /// The model name as text.
        pub fn device_type_str(&self) -> Option<&str> {
            super::text(&self.device_type)
        }
    }
}
