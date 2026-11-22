use core::fmt;

/// Everything that can go wrong while decoding or encoding Remote ID data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before the structure did.
    TooShort {
        /// Bytes the structure needs.
        need: usize,
        /// Bytes that were available.
        got: usize,
    },
    /// The header names a message type that the standard does not define.
    UnknownMessageType(u8),
    /// A message of one type was handed to the decoder of another.
    WrongMessageType {
        /// Type the decoder expected.
        expected: u8,
        /// Type found in the header.
        found: u8,
    },
    /// A message pack broke one of its structural rules.
    InvalidPack(&'static str),
    /// An authentication page header is inconsistent.
    InvalidAuthPage(&'static str),
    /// A value is outside the range the field can carry, so it cannot be encoded.
    OutOfRange(&'static str),
    /// The frame is well formed but carries no Remote ID payload.
    NotRemoteId,
    /// The output buffer is too small.
    BufferTooSmall {
        /// Bytes needed.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// A checksum did not match (DJI DroneID payload CRC).
    ChecksumMismatch {
        /// Checksum computed over the data.
        computed: u16,
        /// Checksum carried in the data.
        found: u16,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooShort { need, got } => {
                write!(f, "input too short: need {need} bytes, got {got}")
            }
            Error::UnknownMessageType(t) => write!(f, "unknown Remote ID message type {t:#x}"),
            Error::WrongMessageType { expected, found } => {
                write!(f, "expected message type {expected:#x}, found {found:#x}")
            }
            Error::InvalidPack(why) => write!(f, "invalid message pack: {why}"),
            Error::InvalidAuthPage(why) => write!(f, "invalid authentication page: {why}"),
            Error::OutOfRange(field) => write!(f, "value out of range for {field}"),
            Error::NotRemoteId => f.write_str("frame carries no Remote ID payload"),
            Error::BufferTooSmall { need, got } => {
                write!(f, "output buffer too small: need {need} bytes, got {got}")
            }
            Error::ChecksumMismatch { computed, found } => {
                write!(
                    f,
                    "checksum mismatch: computed {computed:#06x}, found {found:#06x}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
