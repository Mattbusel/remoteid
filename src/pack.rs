//! Message packs: up to nine messages behind one header.

use crate::{Error, Message, MessageType, MESSAGE_SIZE, PROTOCOL_VERSION};

/// Most messages one pack can hold.
pub const PACK_MAX_MESSAGES: usize = 9;

/// Largest encoded pack: 3 header bytes plus nine messages.
pub const PACK_MAX_SIZE: usize = 3 + PACK_MAX_MESSAGES * MESSAGE_SIZE;

/// A borrowed, structurally checked message pack.
///
/// [`MessagePack::parse`] applies the same rules as the reference library:
/// the single message size must be 25, the pack must hold 1 to 9 messages,
/// it may contain no nested packs or unknown types, and at most one Location,
/// Self ID, System and Operator ID message. Individual messages are decoded
/// lazily by [`MessagePack::messages`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessagePack<'a> {
    protocol_version: u8,
    body: &'a [u8],
}

impl<'a> MessagePack<'a> {
    /// Parses a pack that starts at `data[0]` (the pack header byte).
    /// Bytes after the last message are ignored.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 3 {
            return Err(Error::TooShort {
                need: 3,
                got: data.len(),
            });
        }
        if data[0] >> 4 != u8::from(MessageType::MessagePack) {
            return Err(Error::WrongMessageType {
                expected: 0xF,
                found: data[0] >> 4,
            });
        }
        if data[1] as usize != MESSAGE_SIZE {
            return Err(Error::InvalidPack("single message size is not 25"));
        }
        let count = data[2] as usize;
        if count == 0 {
            return Err(Error::InvalidPack("pack holds no messages"));
        }
        if count > PACK_MAX_MESSAGES {
            return Err(Error::InvalidPack("pack holds more than 9 messages"));
        }
        let need = 3 + count * MESSAGE_SIZE;
        if data.len() < need {
            return Err(Error::TooShort {
                need,
                got: data.len(),
            });
        }
        let body = &data[3..need];
        let mut seen = [0u8; 6];
        for chunk in body.chunks_exact(MESSAGE_SIZE) {
            let t = chunk[0] >> 4;
            if t > 5 {
                return Err(Error::InvalidPack(
                    "pack contains a pack or an unknown message type",
                ));
            }
            seen[t as usize] += 1;
        }
        if seen[1] > 1 || seen[3] > 1 || seen[4] > 1 || seen[5] > 1 {
            return Err(Error::InvalidPack(
                "more than one Location, Self ID, System or Operator ID message",
            ));
        }
        if seen[0] as usize > crate::uas::BASIC_ID_SLOTS {
            return Err(Error::InvalidPack(
                "more Basic ID messages than the standard allows",
            ));
        }
        Ok(MessagePack {
            protocol_version: data[0] & 0x0F,
            body,
        })
    }

    /// Protocol version from the pack header.
    pub fn protocol_version(&self) -> u8 {
        self.protocol_version
    }

    /// Number of messages in the pack.
    pub fn len(&self) -> usize {
        self.body.len() / MESSAGE_SIZE
    }

    /// Always `false`: a valid pack holds at least one message.
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Size of the encoded pack in bytes, header included.
    pub fn encoded_len(&self) -> usize {
        3 + self.body.len()
    }

    /// The raw 25 byte messages.
    pub fn raw_messages(&self) -> impl Iterator<Item = &'a [u8; MESSAGE_SIZE]> + 'a {
        self.body
            .chunks_exact(MESSAGE_SIZE)
            .map(|c| c.try_into().expect("chunk is 25 bytes"))
    }

    /// Decodes each message in turn. A message that fails to decode (for
    /// example an Auth page with an inconsistent header) yields its error
    /// without stopping the others.
    pub fn messages(&self) -> impl Iterator<Item = Result<Message, Error>> + 'a {
        self.raw_messages().map(|raw| Message::decode(raw))
    }
}

/// Builds a message pack into a fixed buffer, without allocating.
///
/// ```
/// use remoteid::{BasicId, IdType, Location, Message, MessagePack, MessagePackBuilder, UaType};
///
/// let mut b = MessagePackBuilder::new();
/// b.push(&Message::BasicId(BasicId::new(IdType::SerialNumber, UaType::HelicopterOrMultirotor, "1596F3507452").unwrap())).unwrap();
/// b.push(&Message::Location(Location { latitude: 51.5, longitude: -0.12, ..Location::default() })).unwrap();
/// let pack = MessagePack::parse(b.as_bytes()).unwrap();
/// assert_eq!(pack.len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct MessagePackBuilder {
    buf: [u8; PACK_MAX_SIZE],
    count: usize,
}

impl Default for MessagePackBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagePackBuilder {
    /// An empty pack with protocol version [`PROTOCOL_VERSION`].
    pub fn new() -> Self {
        let mut buf = [0u8; PACK_MAX_SIZE];
        buf[0] = 0xF0 | PROTOCOL_VERSION;
        buf[1] = MESSAGE_SIZE as u8;
        MessagePackBuilder { buf, count: 0 }
    }

    /// Encodes `msg` and appends it. Fails when the pack is full or the
    /// message does not encode. The type limits are checked by
    /// [`MessagePack::parse`], so a pack that breaks them fails there.
    pub fn push(&mut self, msg: &Message) -> Result<(), Error> {
        self.push_raw(&msg.encode()?)
    }

    /// Appends an already encoded message.
    pub fn push_raw(&mut self, raw: &[u8; MESSAGE_SIZE]) -> Result<(), Error> {
        if self.count == PACK_MAX_MESSAGES {
            return Err(Error::InvalidPack("pack is full"));
        }
        let at = 3 + self.count * MESSAGE_SIZE;
        self.buf[at..at + MESSAGE_SIZE].copy_from_slice(raw);
        self.count += 1;
        self.buf[2] = self.count as u8;
        Ok(())
    }

    /// Number of messages so far.
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` when nothing has been pushed.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The encoded pack.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..3 + self.count * MESSAGE_SIZE]
    }
}
