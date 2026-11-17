//! The six Remote ID message types and their field enums.

use crate::{Error, MESSAGE_SIZE, PROTOCOL_VERSION};

macro_rules! u8_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $( $(#[$vmeta:meta])* $var:ident = $val:literal ),* $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub enum $name {
            $( $(#[$vmeta])* $var, )*
            /// A value the standard reserves or leaves for private use.
            /// Build values with `From<u8>` so known values never land here.
            Other(u8),
        }
        impl From<u8> for $name {
            fn from(v: u8) -> Self {
                match v { $( $val => $name::$var, )* o => $name::Other(o) }
            }
        }
        impl From<$name> for u8 {
            fn from(v: $name) -> u8 {
                match v { $( $name::$var => $val, )* $name::Other(o) => o }
            }
        }
    };
}

u8_enum! {
    /// Message type, the high nibble of every message's first byte.
    pub enum MessageType {
        /// Basic ID: who the aircraft is.
        BasicId = 0,
        /// Location and vector: where it is and where it is going.
        Location = 1,
        /// Authentication data, split over up to 16 pages.
        Auth = 2,
        /// Self ID: free text from the operator.
        SelfId = 3,
        /// System: operator location and the operating area.
        System = 4,
        /// Operator ID: the operator registration number.
        OperatorId = 5,
        /// Several messages packed together.
        MessagePack = 15,
    }
}

u8_enum! {
    /// Kind of identifier in a Basic ID message.
    pub enum IdType {
        /// No identifier.
        None = 0,
        /// Manufacturer serial number (ANSI/CTA-2063-A).
        SerialNumber = 1,
        /// Registration ID issued by a civil aviation authority.
        CaaRegistrationId = 2,
        /// UUID assigned by a UAS traffic management service.
        UtmAssignedUuid = 3,
        /// Session ID; its scheme is given by the first byte of the ID.
        SpecificSessionId = 4,
    }
}

u8_enum! {
    /// Aircraft type in a Basic ID message.
    pub enum UaType {
        /// Not declared.
        None = 0,
        /// Fixed wing.
        Aeroplane = 1,
        /// Helicopter or multirotor.
        HelicopterOrMultirotor = 2,
        /// Gyroplane.
        Gyroplane = 3,
        /// Fixed wing that can take off vertically.
        HybridLift = 4,
        /// Ornithopter.
        Ornithopter = 5,
        /// Glider.
        Glider = 6,
        /// Kite.
        Kite = 7,
        /// Free balloon.
        FreeBalloon = 8,
        /// Captive balloon.
        CaptiveBalloon = 9,
        /// Airship, such as a blimp.
        Airship = 10,
        /// Unpowered free fall or parachute.
        FreeFallParachute = 11,
        /// Rocket.
        Rocket = 12,
        /// Tethered powered aircraft.
        TetheredPoweredAircraft = 13,
        /// Ground obstacle.
        GroundObstacle = 14,
        /// Anything else.
        Unspecified = 15,
    }
}

u8_enum! {
    /// Operational status in a Location message.
    pub enum Status {
        /// Not declared.
        Undeclared = 0,
        /// On the ground.
        Ground = 1,
        /// Airborne.
        Airborne = 2,
        /// Emergency.
        Emergency = 3,
        /// The Remote ID system itself has failed (F3411-22a).
        RemoteIdSystemFailure = 4,
    }
}

u8_enum! {
    /// Reference of the Location message's `height` field.
    pub enum HeightType {
        /// Height above the takeoff point.
        AboveTakeoff = 0,
        /// Height above ground level.
        AboveGround = 1,
    }
}

u8_enum! {
    /// Authentication scheme of an Auth message.
    pub enum AuthType {
        /// None.
        None = 0,
        /// Signature over the UAS ID.
        UasIdSignature = 1,
        /// Signature over the operator ID.
        OperatorIdSignature = 2,
        /// Signature over the message set.
        MessageSetSignature = 3,
        /// Authentication is provided by Network Remote ID.
        NetworkRemoteId = 4,
        /// Specific method, named by the first byte of the data.
        SpecificAuthentication = 5,
    }
}

u8_enum! {
    /// Meaning of the text in a Self ID message.
    pub enum DescriptionType {
        /// Free text.
        Text = 0,
        /// Clarifies an emergency status.
        Emergency = 1,
        /// Clarifies a non-emergency status.
        ExtendedStatus = 2,
    }
}

u8_enum! {
    /// Where the operator position in a System message comes from.
    pub enum OperatorLocationType {
        /// The takeoff point.
        Takeoff = 0,
        /// Live GNSS position of the operator.
        LiveGnss = 1,
        /// A fixed position.
        Fixed = 2,
    }
}

u8_enum! {
    /// Classification scheme in a System message.
    pub enum ClassificationType {
        /// Not declared.
        Undeclared = 0,
        /// European Union classes and categories.
        Eu = 1,
    }
}

u8_enum! {
    /// EU operating category.
    pub enum CategoryEu {
        /// Not declared.
        Undeclared = 0,
        /// Open category.
        Open = 1,
        /// Specific category.
        Specific = 2,
        /// Certified category.
        Certified = 3,
    }
}

u8_enum! {
    /// EU aircraft class.
    pub enum ClassEu {
        /// Not declared.
        Undeclared = 0,
        /// Class C0.
        Class0 = 1,
        /// Class C1.
        Class1 = 2,
        /// Class C2.
        Class2 = 3,
        /// Class C3.
        Class3 = 4,
        /// Class C4.
        Class4 = 5,
        /// Class C5.
        Class5 = 6,
        /// Class C6.
        Class6 = 7,
    }
}

/// Horizontal accuracy code (0 to 15) from a Location message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HorizontalAccuracy(pub u8);

impl HorizontalAccuracy {
    /// The accuracy bound in meters, or `None` for unknown and reserved codes.
    pub fn meters(self) -> Option<f32> {
        Some(match self.0 {
            1 => 18520.0,
            2 => 7408.0,
            3 => 3704.0,
            4 => 1852.0,
            5 => 926.0,
            6 => 555.6,
            7 => 185.2,
            8 => 92.6,
            9 => 30.0,
            10 => 10.0,
            11 => 3.0,
            12 => 1.0,
            _ => return None,
        })
    }

    /// The smallest code whose bound covers `meters`, the same rule the
    /// reference library uses. Returns code 0 (unknown) above 18.52 km.
    pub fn from_meters(meters: f32) -> Self {
        let table = [
            1.0, 3.0, 10.0, 30.0, 92.6, 185.2, 555.6, 926.0, 1852.0, 3704.0, 7408.0, 18520.0,
        ];
        for (i, bound) in table.iter().enumerate() {
            if meters < *bound {
                return HorizontalAccuracy(12 - i as u8);
            }
        }
        HorizontalAccuracy(0)
    }
}

/// Vertical (geodetic or barometric) accuracy code from a Location message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerticalAccuracy(pub u8);

impl VerticalAccuracy {
    /// The accuracy bound in meters, or `None` for unknown and reserved codes.
    pub fn meters(self) -> Option<f32> {
        Some(match self.0 {
            1 => 150.0,
            2 => 45.0,
            3 => 25.0,
            4 => 10.0,
            5 => 3.0,
            6 => 1.0,
            _ => return None,
        })
    }

    /// The smallest code whose bound covers `meters`. Returns code 0 above 150 m.
    pub fn from_meters(meters: f32) -> Self {
        let table = [1.0, 3.0, 10.0, 25.0, 45.0, 150.0];
        for (i, bound) in table.iter().enumerate() {
            if meters < *bound {
                return VerticalAccuracy(6 - i as u8);
            }
        }
        VerticalAccuracy(0)
    }
}

/// Speed accuracy code from a Location message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpeedAccuracy(pub u8);

impl SpeedAccuracy {
    /// The accuracy bound in meters per second, or `None` for unknown and reserved codes.
    pub fn meters_per_second(self) -> Option<f32> {
        Some(match self.0 {
            1 => 10.0,
            2 => 3.0,
            3 => 1.0,
            4 => 0.3,
            _ => return None,
        })
    }

    /// The smallest code whose bound covers `mps`. Returns code 0 above 10 m/s.
    pub fn from_meters_per_second(mps: f32) -> Self {
        let table = [0.3, 1.0, 3.0, 10.0];
        for (i, bound) in table.iter().enumerate() {
            if mps < *bound {
                return SpeedAccuracy(4 - i as u8);
            }
        }
        SpeedAccuracy(0)
    }
}

/// Timestamp accuracy code from a Location message, in tenths of a second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimestampAccuracy(pub u8);

impl TimestampAccuracy {
    /// The accuracy bound in seconds (0.1 to 1.5), or `None` when unknown.
    pub fn seconds(self) -> Option<f32> {
        match self.0 {
            1..=15 => Some(self.0 as f32 / 10.0),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Numeric codecs. They mirror opendroneid-core-c, including its rounding
// (half away from zero) and its use of f32 arithmetic, so encoded bytes match.
// ---------------------------------------------------------------------------

const LATLON_MULT: f64 = 10_000_000.0;
/// Seconds from the Unix epoch to 2019-01-01 00:00:00 UTC, the epoch of the
/// System and Auth timestamps.
pub const EPOCH_2019_UNIX: u64 = 1_546_300_800;

fn round_f32(x: f32) -> i64 {
    if x >= 0.0 {
        (x as f64 + 0.5) as i64
    } else {
        (x as f64 - 0.5) as i64
    }
}

fn round_f64(x: f64) -> i64 {
    if x >= 0.0 {
        (x + 0.5) as i64
    } else {
        (x - 0.5) as i64
    }
}

fn clamp(v: i64, lo: i64, hi: i64) -> i64 {
    v.max(lo).min(hi)
}

fn decode_latlon(raw: i32) -> f64 {
    raw as f64 / LATLON_MULT
}

fn encode_latlon(v: f64) -> i32 {
    clamp(round_f64(v * LATLON_MULT), -1_800_000_000, 1_800_000_000) as i32
}

/// Altitude encoding: 0.5 m steps from -1000 m. Raw 0 (-1000 m) means unknown.
fn decode_altitude(raw: u16) -> Option<f32> {
    if raw == 0 {
        None
    } else {
        Some(raw as f32 * 0.5 - 1000.0)
    }
}

fn encode_altitude(v: Option<f32>, field: &'static str) -> Result<u16, Error> {
    match v {
        None => Ok(0),
        Some(m) if !(-1000.0..=31767.5).contains(&m) => Err(Error::OutOfRange(field)),
        Some(m) => Ok(clamp(round_f32((m + 1000.0) / 0.5), 0, u16::MAX as i64) as u16),
    }
}

fn read_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn read_i32(b: &[u8], at: usize) -> i32 {
    i32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn read_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn nibble(v: u8, field: &'static str) -> Result<u8, Error> {
    if v > 15 {
        Err(Error::OutOfRange(field))
    } else {
        Ok(v)
    }
}

fn header(t: MessageType, version: u8) -> Result<u8, Error> {
    Ok((u8::from(t) << 4) | nibble(version, "protocol_version")?)
}

/// Returns the text in a NUL padded field, or `None` if it is not printable ASCII.
fn padded_str(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s = &bytes[..end];
    if s.iter().all(|b| (0x20..0x7f).contains(b)) {
        core::str::from_utf8(s).ok()
    } else {
        None
    }
}

/// Copies `text` into a NUL padded field. Fails if it does not fit.
fn fill_padded<const N: usize>(text: &str, field: &'static str) -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    if text.len() > N {
        return Err(Error::OutOfRange(field));
    }
    out[..text.len()].copy_from_slice(text.as_bytes());
    Ok(out)
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// One decoded Remote ID message.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Message {
    /// Basic ID.
    BasicId(BasicId),
    /// Location and vector.
    Location(Location),
    /// One authentication page.
    Auth(Auth),
    /// Self ID.
    SelfId(SelfId),
    /// System.
    System(System),
    /// Operator ID.
    OperatorId(OperatorId),
}

impl Message {
    /// Decodes one message from the first [`MESSAGE_SIZE`] bytes of `data`.
    ///
    /// A message pack header is rejected here; use [`crate::Frame::decode`]
    /// or [`crate::MessagePack::parse`] for packs.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < MESSAGE_SIZE {
            return Err(Error::TooShort {
                need: MESSAGE_SIZE,
                got: data.len(),
            });
        }
        let raw: &[u8; MESSAGE_SIZE] = data[..MESSAGE_SIZE].try_into().expect("length checked");
        Ok(match MessageType::from(raw[0] >> 4) {
            MessageType::BasicId => Message::BasicId(BasicId::decode(raw)?),
            MessageType::Location => Message::Location(Location::decode(raw)?),
            MessageType::Auth => Message::Auth(Auth::decode(raw)?),
            MessageType::SelfId => Message::SelfId(SelfId::decode(raw)?),
            MessageType::System => Message::System(System::decode(raw)?),
            MessageType::OperatorId => Message::OperatorId(OperatorId::decode(raw)?),
            MessageType::MessagePack | MessageType::Other(_) => {
                return Err(Error::UnknownMessageType(raw[0] >> 4))
            }
        })
    }

    /// Encodes the message into its 25 byte broadcast form.
    pub fn encode(&self) -> Result<[u8; MESSAGE_SIZE], Error> {
        match self {
            Message::BasicId(m) => m.encode(),
            Message::Location(m) => m.encode(),
            Message::Auth(m) => m.encode(),
            Message::SelfId(m) => m.encode(),
            Message::System(m) => m.encode(),
            Message::OperatorId(m) => m.encode(),
        }
    }

    /// The message type.
    pub fn message_type(&self) -> MessageType {
        match self {
            Message::BasicId(_) => MessageType::BasicId,
            Message::Location(_) => MessageType::Location,
            Message::Auth(_) => MessageType::Auth,
            Message::SelfId(_) => MessageType::SelfId,
            Message::System(_) => MessageType::System,
            Message::OperatorId(_) => MessageType::OperatorId,
        }
    }

    /// The protocol version from the message header.
    pub fn protocol_version(&self) -> u8 {
        match self {
            Message::BasicId(m) => m.protocol_version,
            Message::Location(m) => m.protocol_version,
            Message::Auth(m) => m.protocol_version,
            Message::SelfId(m) => m.protocol_version,
            Message::System(m) => m.protocol_version,
            Message::OperatorId(m) => m.protocol_version,
        }
    }
}

fn expect_type(raw: &[u8; MESSAGE_SIZE], t: MessageType) -> Result<u8, Error> {
    let found = raw[0] >> 4;
    if found != u8::from(t) {
        return Err(Error::WrongMessageType {
            expected: t.into(),
            found,
        });
    }
    Ok(raw[0] & 0x0F)
}

/// Basic ID message: the aircraft's identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicId {
    /// Protocol version from the header.
    pub protocol_version: u8,
    /// Kind of identifier.
    pub id_type: IdType,
    /// Aircraft type.
    pub ua_type: UaType,
    /// The identifier, NUL padded. Serial numbers and registration IDs are
    /// ASCII; UUIDs and session IDs are binary.
    pub uas_id: [u8; 20],
}

impl BasicId {
    /// Builds a Basic ID message with a text identifier.
    pub fn new(id_type: IdType, ua_type: UaType, uas_id: &str) -> Result<Self, Error> {
        Ok(BasicId {
            protocol_version: PROTOCOL_VERSION,
            id_type,
            ua_type,
            uas_id: fill_padded(uas_id, "uas_id")?,
        })
    }

    /// Decodes a Basic ID message.
    pub fn decode(raw: &[u8; MESSAGE_SIZE]) -> Result<Self, Error> {
        let protocol_version = expect_type(raw, MessageType::BasicId)?;
        let mut uas_id = [0u8; 20];
        uas_id.copy_from_slice(&raw[2..22]);
        Ok(BasicId {
            protocol_version,
            id_type: IdType::from(raw[1] >> 4),
            ua_type: UaType::from(raw[1] & 0x0F),
            uas_id,
        })
    }

    /// Encodes the message.
    pub fn encode(&self) -> Result<[u8; MESSAGE_SIZE], Error> {
        let mut out = [0u8; MESSAGE_SIZE];
        out[0] = header(MessageType::BasicId, self.protocol_version)?;
        out[1] = (nibble(self.id_type.into(), "id_type")? << 4)
            | nibble(self.ua_type.into(), "ua_type")?;
        out[2..22].copy_from_slice(&self.uas_id);
        Ok(out)
    }

    /// The identifier as text, if it is printable ASCII (serial numbers and
    /// registration IDs are). Trailing NUL padding is removed.
    pub fn uas_id_str(&self) -> Option<&str> {
        padded_str(&self.uas_id)
    }

    /// Splits an ANSI/CTA-2063-A serial number into its parts, if the ID is
    /// one and its length character matches the serial that follows.
    pub fn serial_number(&self) -> Option<SerialNumber<'_>> {
        if self.id_type != IdType::SerialNumber {
            return None;
        }
        SerialNumber::parse(self.uas_id_str()?)
    }
}

/// An ANSI/CTA-2063-A physical serial number: a 4 character manufacturer
/// code, one length character (1 to 9, A to F) and the serial itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SerialNumber<'a> {
    /// Manufacturer code assigned by ICAO, 4 characters.
    pub manufacturer_code: &'a str,
    /// Length of the serial, decoded from the length character.
    pub length: u8,
    /// The manufacturer's serial number.
    pub serial: &'a str,
}

impl<'a> SerialNumber<'a> {
    /// Parses and checks a serial number string.
    ///
    /// The manufacturer code and serial use digits and upper case letters,
    /// excluding `O` and `I`. The length character must match the serial.
    pub fn parse(s: &'a str) -> Option<Self> {
        let allowed =
            |c: u8| (c.is_ascii_digit() || c.is_ascii_uppercase()) && c != b'O' && c != b'I';
        let b = s.as_bytes();
        if b.len() < 6 || b.len() > 20 {
            return None;
        }
        let length = match b[4] {
            c @ b'1'..=b'9' => c - b'0',
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        if b.len() != 5 + length as usize
            || !b[..4].iter().copied().all(allowed)
            || !b[5..].iter().copied().all(allowed)
        {
            return None;
        }
        Some(SerialNumber {
            manufacturer_code: &s[..4],
            length,
            serial: &s[5..],
        })
    }
}

/// Location and vector message.
///
/// Fields the transmitter marks as unknown decode to `None`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Location {
    /// Protocol version from the header.
    pub protocol_version: u8,
    /// Operational status.
    pub status: Status,
    /// Reference of `height`.
    pub height_type: HeightType,
    /// Track over ground in degrees clockwise from true north, 0 to 359.
    pub direction: Option<f32>,
    /// Ground speed in m/s (0.25 m/s steps up to 63.75, then 0.75 m/s steps up to 254.25).
    pub speed_horizontal: Option<f32>,
    /// Vertical speed in m/s, positive up, 0.5 m/s steps, -62 to 62.
    pub speed_vertical: Option<f32>,
    /// Latitude in degrees. 0 together with longitude 0 means unknown, see [`Location::position`].
    pub latitude: f64,
    /// Longitude in degrees.
    pub longitude: f64,
    /// Pressure altitude in meters (standard atmosphere).
    pub altitude_baro: Option<f32>,
    /// Geodetic altitude in meters above the WGS84 ellipsoid.
    pub altitude_geo: Option<f32>,
    /// Height in meters above the reference in `height_type`.
    pub height: Option<f32>,
    /// Horizontal accuracy code.
    pub horizontal_accuracy: HorizontalAccuracy,
    /// Geodetic altitude accuracy code.
    pub vertical_accuracy: VerticalAccuracy,
    /// Pressure altitude accuracy code.
    pub baro_accuracy: VerticalAccuracy,
    /// Speed accuracy code.
    pub speed_accuracy: SpeedAccuracy,
    /// Timestamp accuracy code.
    pub timestamp_accuracy: TimestampAccuracy,
    /// Time of the position in seconds after the full UTC hour, 0.1 s steps.
    pub timestamp: Option<f32>,
}

impl Default for Location {
    fn default() -> Self {
        Location {
            protocol_version: PROTOCOL_VERSION,
            status: Status::Undeclared,
            height_type: HeightType::AboveTakeoff,
            direction: None,
            speed_horizontal: None,
            speed_vertical: None,
            latitude: 0.0,
            longitude: 0.0,
            altitude_baro: None,
            altitude_geo: None,
            height: None,
            horizontal_accuracy: HorizontalAccuracy(0),
            vertical_accuracy: VerticalAccuracy(0),
            baro_accuracy: VerticalAccuracy(0),
            speed_accuracy: SpeedAccuracy(0),
            timestamp_accuracy: TimestampAccuracy(0),
            timestamp: None,
        }
    }
}

/// A plausibility problem found by [`Location::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocationIssue {
    /// Latitude outside -90 to 90 degrees.
    LatitudeOutOfRange,
    /// Longitude outside -180 to 180 degrees.
    LongitudeOutOfRange,
    /// Direction decoded above 359 degrees (east/west flag set on a value of 180 or more).
    DirectionOutOfRange,
    /// Vertical speed beyond the +-62 m/s the field allows.
    VerticalSpeedOutOfRange,
    /// Timestamp beyond one hour (3600.0 s).
    TimestampOutOfRange,
    /// Status, height type or an accuracy uses a reserved code.
    ReservedCode,
}

impl Location {
    /// Decodes a Location message.
    pub fn decode(raw: &[u8; MESSAGE_SIZE]) -> Result<Self, Error> {
        let protocol_version = expect_type(raw, MessageType::Location)?;
        let flags = raw[1];
        let speed_mult = flags & 0x01 != 0;
        let ew = flags & 0x02 != 0;

        let dir = raw[2] as f32 + if ew { 180.0 } else { 0.0 };
        let speed = if speed_mult {
            raw[3] as f32 * 0.75 + 255.0 * 0.25
        } else {
            raw[3] as f32 * 0.25
        };
        let vspeed = (raw[4] as i8) as f32 * 0.5;
        let ts = read_u16(raw, 21);

        Ok(Location {
            protocol_version,
            status: Status::from(flags >> 4),
            height_type: HeightType::from((flags >> 2) & 0x01),
            direction: if dir == 361.0 { None } else { Some(dir) },
            speed_horizontal: if speed == 255.0 { None } else { Some(speed) },
            speed_vertical: if vspeed == 63.0 { None } else { Some(vspeed) },
            latitude: decode_latlon(read_i32(raw, 5)),
            longitude: decode_latlon(read_i32(raw, 9)),
            altitude_baro: decode_altitude(read_u16(raw, 13)),
            altitude_geo: decode_altitude(read_u16(raw, 15)),
            height: decode_altitude(read_u16(raw, 17)),
            horizontal_accuracy: HorizontalAccuracy(raw[19] & 0x0F),
            vertical_accuracy: VerticalAccuracy(raw[19] >> 4),
            speed_accuracy: SpeedAccuracy(raw[20] & 0x0F),
            baro_accuracy: VerticalAccuracy(raw[20] >> 4),
            timestamp: if ts == 0xFFFF {
                None
            } else {
                Some(ts as f32 / 10.0)
            },
            timestamp_accuracy: TimestampAccuracy(raw[23] & 0x0F),
        })
    }

    /// Encodes the message, rejecting values outside the field ranges.
    pub fn encode(&self) -> Result<[u8; MESSAGE_SIZE], Error> {
        let mut out = [0u8; MESSAGE_SIZE];
        out[0] = header(MessageType::Location, self.protocol_version)?;

        let (dir_raw, ew) = match self.direction {
            None => (181u8, true),
            Some(d) if !(0.0..=360.0).contains(&d) => return Err(Error::OutOfRange("direction")),
            Some(d) => {
                let mut di = round_f32(d);
                if di == 360 {
                    di = 0;
                }
                if di < 180 {
                    (di as u8, false)
                } else {
                    ((di - 180) as u8, true)
                }
            }
        };
        let (speed_raw, mult) = match self.speed_horizontal {
            None => (255u8, true),
            Some(s) if !(0.0..=254.25).contains(&s) => {
                return Err(Error::OutOfRange("speed_horizontal"))
            }
            Some(s) if s <= 255.0 * 0.25 => (round_f32(s / 0.25) as u8, false),
            Some(s) => (
                clamp(round_f32((s - 255.0 * 0.25) / 0.75), 0, 255) as u8,
                true,
            ),
        };
        let vs_raw = match self.speed_vertical {
            None => 126i8,
            Some(v) if !(-62.0..=62.0).contains(&v) => {
                return Err(Error::OutOfRange("speed_vertical"))
            }
            Some(v) => clamp(round_f32(v / 0.5), -128, 127) as i8,
        };
        if !(-90.0..=90.0).contains(&self.latitude) {
            return Err(Error::OutOfRange("latitude"));
        }
        if !(-180.0..=180.0).contains(&self.longitude) {
            return Err(Error::OutOfRange("longitude"));
        }
        let ts_raw: u16 = match self.timestamp {
            None => 0xFFFF,
            Some(t) if !(0.0..=3600.0).contains(&t) => return Err(Error::OutOfRange("timestamp")),
            Some(t) => clamp(round_f32(t * 10.0), 0, 36000) as u16,
        };

        out[1] = (nibble(self.status.into(), "status")? << 4)
            | ((u8::from(self.height_type) & 0x01) << 2)
            | ((ew as u8) << 1)
            | mult as u8;
        if u8::from(self.height_type) > 1 {
            return Err(Error::OutOfRange("height_type"));
        }
        out[2] = dir_raw;
        out[3] = speed_raw;
        out[4] = vs_raw as u8;
        out[5..9].copy_from_slice(&encode_latlon(self.latitude).to_le_bytes());
        out[9..13].copy_from_slice(&encode_latlon(self.longitude).to_le_bytes());
        out[13..15]
            .copy_from_slice(&encode_altitude(self.altitude_baro, "altitude_baro")?.to_le_bytes());
        out[15..17]
            .copy_from_slice(&encode_altitude(self.altitude_geo, "altitude_geo")?.to_le_bytes());
        out[17..19].copy_from_slice(&encode_altitude(self.height, "height")?.to_le_bytes());
        out[19] = (nibble(self.vertical_accuracy.0, "vertical_accuracy")? << 4)
            | nibble(self.horizontal_accuracy.0, "horizontal_accuracy")?;
        out[20] = (nibble(self.baro_accuracy.0, "baro_accuracy")? << 4)
            | nibble(self.speed_accuracy.0, "speed_accuracy")?;
        out[21..23].copy_from_slice(&ts_raw.to_le_bytes());
        out[23] = nibble(self.timestamp_accuracy.0, "timestamp_accuracy")?;
        Ok(out)
    }

    /// Latitude and longitude, or `None` when the transmitter sent 0, 0 (unknown).
    pub fn position(&self) -> Option<(f64, f64)> {
        if self.latitude == 0.0 && self.longitude == 0.0 {
            None
        } else {
            Some((self.latitude, self.longitude))
        }
    }

    /// Checks the decoded values against the ranges the standard allows and
    /// reports every problem found. The decoder itself accepts any bit
    /// pattern (as the reference library does), so receivers that want to
    /// drop corrupted or spoofed frames should call this.
    pub fn check(&self) -> impl Iterator<Item = LocationIssue> {
        let mut found = [None; 6];
        if !(-90.0..=90.0).contains(&self.latitude) {
            found[0] = Some(LocationIssue::LatitudeOutOfRange);
        }
        if !(-180.0..=180.0).contains(&self.longitude) {
            found[1] = Some(LocationIssue::LongitudeOutOfRange);
        }
        if self.direction.is_some_and(|d| d >= 360.0) {
            found[2] = Some(LocationIssue::DirectionOutOfRange);
        }
        if self
            .speed_vertical
            .is_some_and(|v| !(-62.0..=62.0).contains(&v))
        {
            found[3] = Some(LocationIssue::VerticalSpeedOutOfRange);
        }
        if self.timestamp.is_some_and(|t| t > 3600.0) {
            found[4] = Some(LocationIssue::TimestampOutOfRange);
        }
        if matches!(self.status, Status::Other(_))
            || self.horizontal_accuracy.0 > 12
            || self.vertical_accuracy.0 > 6
            || self.baro_accuracy.0 > 6
            || self.speed_accuracy.0 > 4
        {
            found[5] = Some(LocationIssue::ReservedCode);
        }
        found.into_iter().flatten()
    }

    /// `true` if [`Location::check`] finds nothing.
    pub fn is_plausible(&self) -> bool {
        self.check().next().is_none()
    }
}

/// One page of an authentication message.
///
/// Page 0 carries the header fields and 17 data bytes; pages 1 to 15 carry
/// 23 data bytes each. [`crate::UasData::auth_data`] joins the pages.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Auth {
    /// Protocol version from the header.
    pub protocol_version: u8,
    /// Authentication scheme.
    pub auth_type: AuthType,
    /// Page number, 0 to 15.
    pub page: u8,
    /// Page 0 only: index of the last page.
    pub last_page_index: u8,
    /// Page 0 only: total length of the authentication data in bytes.
    pub length: u8,
    /// Page 0 only: seconds since 2019-01-01 00:00:00 UTC.
    pub timestamp: u32,
    /// Data bytes of this page (17 on page 0, 23 on others; the rest is zero).
    pub data: [u8; 23],
}

impl Auth {
    /// Decodes an authentication page, with the same consistency checks as
    /// the reference library (page 0 must announce a length that fits in
    /// its pages).
    pub fn decode(raw: &[u8; MESSAGE_SIZE]) -> Result<Self, Error> {
        let protocol_version = expect_type(raw, MessageType::Auth)?;
        let page = raw[1] & 0x0F;
        let auth_type = AuthType::from(raw[1] >> 4);
        let mut data = [0u8; 23];
        if page == 0 {
            let last_page_index = raw[2];
            let length = raw[3];
            if last_page_index >= 16 {
                return Err(Error::InvalidAuthPage("last page index above 15"));
            }
            if (length as usize) > 17 + last_page_index as usize * 23 {
                return Err(Error::InvalidAuthPage(
                    "length does not fit in the announced pages",
                ));
            }
            data[..17].copy_from_slice(&raw[8..25]);
            Ok(Auth {
                protocol_version,
                auth_type,
                page,
                last_page_index,
                length,
                timestamp: read_u32(raw, 4),
                data,
            })
        } else {
            data.copy_from_slice(&raw[2..25]);
            Ok(Auth {
                protocol_version,
                auth_type,
                page,
                last_page_index: 0,
                length: 0,
                timestamp: 0,
                data,
            })
        }
    }

    /// Encodes the page.
    pub fn encode(&self) -> Result<[u8; MESSAGE_SIZE], Error> {
        let mut out = [0u8; MESSAGE_SIZE];
        out[0] = header(MessageType::Auth, self.protocol_version)?;
        out[1] = (nibble(self.auth_type.into(), "auth_type")? << 4) | nibble(self.page, "page")?;
        if self.page == 0 {
            if self.last_page_index >= 16 {
                return Err(Error::OutOfRange("last_page_index"));
            }
            if (self.length as usize) > 17 + self.last_page_index as usize * 23 {
                return Err(Error::OutOfRange("length"));
            }
            out[2] = self.last_page_index;
            out[3] = self.length;
            out[4..8].copy_from_slice(&self.timestamp.to_le_bytes());
            out[8..25].copy_from_slice(&self.data[..17]);
        } else {
            out[2..25].copy_from_slice(&self.data);
        }
        Ok(out)
    }

    /// The data bytes this page carries (17 on page 0, 23 otherwise).
    pub fn page_data(&self) -> &[u8] {
        if self.page == 0 {
            &self.data[..17]
        } else {
            &self.data
        }
    }

    /// Page 0 timestamp as Unix seconds.
    pub fn unix_timestamp(&self) -> u64 {
        self.timestamp as u64 + EPOCH_2019_UNIX
    }
}

/// Self ID message: free text from the operator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SelfId {
    /// Protocol version from the header.
    pub protocol_version: u8,
    /// What the text describes.
    pub description_type: DescriptionType,
    /// The text, NUL padded.
    pub description: [u8; 23],
}

impl SelfId {
    /// Builds a Self ID message.
    pub fn new(description_type: DescriptionType, text: &str) -> Result<Self, Error> {
        Ok(SelfId {
            protocol_version: PROTOCOL_VERSION,
            description_type,
            description: fill_padded(text, "description")?,
        })
    }

    /// Decodes a Self ID message.
    pub fn decode(raw: &[u8; MESSAGE_SIZE]) -> Result<Self, Error> {
        let protocol_version = expect_type(raw, MessageType::SelfId)?;
        let mut description = [0u8; 23];
        description.copy_from_slice(&raw[2..25]);
        Ok(SelfId {
            protocol_version,
            description_type: DescriptionType::from(raw[1]),
            description,
        })
    }

    /// Encodes the message.
    pub fn encode(&self) -> Result<[u8; MESSAGE_SIZE], Error> {
        let mut out = [0u8; MESSAGE_SIZE];
        out[0] = header(MessageType::SelfId, self.protocol_version)?;
        out[1] = self.description_type.into();
        out[2..25].copy_from_slice(&self.description);
        Ok(out)
    }

    /// The text, if it is printable ASCII.
    pub fn description_str(&self) -> Option<&str> {
        padded_str(&self.description)
    }
}

/// System message: operator position and the operating area.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct System {
    /// Protocol version from the header.
    pub protocol_version: u8,
    /// Source of the operator position.
    pub operator_location_type: OperatorLocationType,
    /// Classification scheme.
    pub classification_type: ClassificationType,
    /// Operator latitude in degrees (0, 0 means unknown).
    pub operator_latitude: f64,
    /// Operator longitude in degrees.
    pub operator_longitude: f64,
    /// Number of aircraft in the group (1 for a single aircraft).
    pub area_count: u16,
    /// Radius of the group's area in meters, 10 m steps up to 2550.
    pub area_radius: u16,
    /// Area ceiling in meters (WGS84).
    pub area_ceiling: Option<f32>,
    /// Area floor in meters (WGS84).
    pub area_floor: Option<f32>,
    /// EU category, when `classification_type` is EU.
    pub category_eu: CategoryEu,
    /// EU class, when `classification_type` is EU.
    pub class_eu: ClassEu,
    /// Operator altitude in meters above the WGS84 ellipsoid.
    pub operator_altitude_geo: Option<f32>,
    /// Seconds since 2019-01-01 00:00:00 UTC (0 when the transmitter predates F3411-22a).
    pub timestamp: u32,
}

impl Default for System {
    fn default() -> Self {
        System {
            protocol_version: PROTOCOL_VERSION,
            operator_location_type: OperatorLocationType::Takeoff,
            classification_type: ClassificationType::Undeclared,
            operator_latitude: 0.0,
            operator_longitude: 0.0,
            area_count: 1,
            area_radius: 0,
            area_ceiling: None,
            area_floor: None,
            category_eu: CategoryEu::Undeclared,
            class_eu: ClassEu::Undeclared,
            operator_altitude_geo: None,
            timestamp: 0,
        }
    }
}

impl System {
    /// Decodes a System message.
    pub fn decode(raw: &[u8; MESSAGE_SIZE]) -> Result<Self, Error> {
        let protocol_version = expect_type(raw, MessageType::System)?;
        Ok(System {
            protocol_version,
            operator_location_type: OperatorLocationType::from(raw[1] & 0x03),
            classification_type: ClassificationType::from((raw[1] >> 2) & 0x07),
            operator_latitude: decode_latlon(read_i32(raw, 2)),
            operator_longitude: decode_latlon(read_i32(raw, 6)),
            area_count: read_u16(raw, 10),
            area_radius: raw[12] as u16 * 10,
            area_ceiling: decode_altitude(read_u16(raw, 13)),
            area_floor: decode_altitude(read_u16(raw, 15)),
            category_eu: CategoryEu::from(raw[17] >> 4),
            class_eu: ClassEu::from(raw[17] & 0x0F),
            operator_altitude_geo: decode_altitude(read_u16(raw, 18)),
            timestamp: read_u32(raw, 20),
        })
    }

    /// Encodes the message.
    pub fn encode(&self) -> Result<[u8; MESSAGE_SIZE], Error> {
        let mut out = [0u8; MESSAGE_SIZE];
        out[0] = header(MessageType::System, self.protocol_version)?;
        let olt = u8::from(self.operator_location_type);
        let ct = u8::from(self.classification_type);
        if olt > 3 {
            return Err(Error::OutOfRange("operator_location_type"));
        }
        if ct > 7 {
            return Err(Error::OutOfRange("classification_type"));
        }
        if !(-90.0..=90.0).contains(&self.operator_latitude) {
            return Err(Error::OutOfRange("operator_latitude"));
        }
        if !(-180.0..=180.0).contains(&self.operator_longitude) {
            return Err(Error::OutOfRange("operator_longitude"));
        }
        if self.area_radius > 2550 {
            return Err(Error::OutOfRange("area_radius"));
        }
        out[1] = (ct << 2) | olt;
        out[2..6].copy_from_slice(&encode_latlon(self.operator_latitude).to_le_bytes());
        out[6..10].copy_from_slice(&encode_latlon(self.operator_longitude).to_le_bytes());
        out[10..12].copy_from_slice(&self.area_count.to_le_bytes());
        out[12] = (self.area_radius / 10) as u8;
        out[13..15]
            .copy_from_slice(&encode_altitude(self.area_ceiling, "area_ceiling")?.to_le_bytes());
        out[15..17].copy_from_slice(&encode_altitude(self.area_floor, "area_floor")?.to_le_bytes());
        out[17] = (nibble(self.category_eu.into(), "category_eu")? << 4)
            | nibble(self.class_eu.into(), "class_eu")?;
        out[18..20].copy_from_slice(
            &encode_altitude(self.operator_altitude_geo, "operator_altitude_geo")?.to_le_bytes(),
        );
        out[20..24].copy_from_slice(&self.timestamp.to_le_bytes());
        Ok(out)
    }

    /// Operator latitude and longitude, or `None` for 0, 0 (unknown).
    pub fn operator_position(&self) -> Option<(f64, f64)> {
        if self.operator_latitude == 0.0 && self.operator_longitude == 0.0 {
            None
        } else {
            Some((self.operator_latitude, self.operator_longitude))
        }
    }

    /// The timestamp as Unix seconds, or `None` when it is 0 (not sent).
    pub fn unix_timestamp(&self) -> Option<u64> {
        if self.timestamp == 0 {
            None
        } else {
            Some(self.timestamp as u64 + EPOCH_2019_UNIX)
        }
    }
}

/// Operator ID message: the operator's registration number.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OperatorId {
    /// Protocol version from the header.
    pub protocol_version: u8,
    /// Kind of operator ID (0 is the only value the standard defines).
    pub operator_id_type: u8,
    /// The operator ID, NUL padded.
    pub operator_id: [u8; 20],
}

impl OperatorId {
    /// Builds an Operator ID message (type 0).
    pub fn new(operator_id: &str) -> Result<Self, Error> {
        Ok(OperatorId {
            protocol_version: PROTOCOL_VERSION,
            operator_id_type: 0,
            operator_id: fill_padded(operator_id, "operator_id")?,
        })
    }

    /// Decodes an Operator ID message.
    pub fn decode(raw: &[u8; MESSAGE_SIZE]) -> Result<Self, Error> {
        let protocol_version = expect_type(raw, MessageType::OperatorId)?;
        let mut operator_id = [0u8; 20];
        operator_id.copy_from_slice(&raw[2..22]);
        Ok(OperatorId {
            protocol_version,
            operator_id_type: raw[1],
            operator_id,
        })
    }

    /// Encodes the message.
    pub fn encode(&self) -> Result<[u8; MESSAGE_SIZE], Error> {
        let mut out = [0u8; MESSAGE_SIZE];
        out[0] = header(MessageType::OperatorId, self.protocol_version)?;
        out[1] = self.operator_id_type;
        out[2..22].copy_from_slice(&self.operator_id);
        Ok(out)
    }

    /// The operator ID, if it is printable ASCII.
    pub fn operator_id_str(&self) -> Option<&str> {
        padded_str(&self.operator_id)
    }
}
