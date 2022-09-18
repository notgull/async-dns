//! An implementation of the DNS protocol, [sans I/O].
//!
//! [sans I/O]: https://sans-io.readthedocs.io/
//!
//! This crate implements the Domain System Protocol, used for namespace lookups among
//! other things. It is intended to be used in conjunction with a transport layer, such
//! as UDP, TCP or HTTPS The goal of this crate is to provide a runtime and protocol-agnostic
//! implementation of the DNS protocol, so that it can be used in a variety of contexts.
//!
//! This crate is not only `no_std`, it does not use an allocator as well. This means that it
//! can be used on embedded systems that do not have allocators, and that it does no allocation
//! of its own. However, this comes with a catch: the user is expected to provide their own
//! buffers for the various operations. This is done to avoid the need for an allocator, and
//! to allow the user to control the memory usage of the library.
//!
//! This crate is also `#![forbid(unsafe_code)]`, and is intended to remain so.
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use dns_protocol::{Message, Question, ResourceRecord, ResourceType, Flags};
//! use std::net::UdpSocket;
//!
//! // Allocate a buffer for the message.
//! let mut buf = vec![0; 1024];
//!
//! // Create a message. This is a query for the A record of example.com.
//! let mut questions = [
//!     Question::new(
//!         "example.com",
//!         ResourceType::A,
//!         0,
//!     )
//! ];
//! let mut answers = [ResourceRecord::default()];
//! let message = Message::new(0x42, Flags::default(), &mut questions, &mut answers, &mut [], &mut []);
//!
//! // Serialize the message into the buffer
//! assert!(message.space_needed() <= buf.len());
//! let len = message.write(&mut buf)?;
//!
//! // Write the buffer to the socket.
//! let socket = UdpSocket::bind("localhost:0")?;
//! socket.send_to(&buf[..len], "1.2.3.4:53")?;
//!
//! // Read new data from the socket.
//! let data_len = socket.recv(&mut buf)?;
//!
//! // Parse the data as a message.
//! let message = Message::read(
//!     &buf[..data_len],
//!     &mut questions,
//!     &mut answers,
//!     &mut [],
//!     &mut [],
//! )?;
//!
//! // Read the answer from the message.
//! let answer = message.answers()[0];
//! println!("Answer Data: {:?}", answer.data());
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - `std` (enabled by default) - Enables the `std` library for use in `Error` types.
//!   Disable this feature to use on `no_std` targets.
//! ```

#![forbid(
    unsafe_code,
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    future_incompatible
)]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

use core::convert::{TryFrom, TryInto};
use core::fmt;
use core::iter;
use core::mem;
use core::num::NonZeroUsize;
use core::str;

#[cfg(feature = "std")]
use std::error::Error as StdError;

mod ser;
use ser::{Cursor, Serialize};
pub use ser::{Label, LabelSegment};

/// Macro to implement `Serialize` for a struct.
macro_rules! serialize {
    (
        $(#[$outer:meta])*
        pub struct $name:ident $(<$lt: lifetime>)? {
            $(
                $(#[$inner:meta])*
                $vis: vis $field:ident: $ty:ty,
            )*
        }
    ) => {
        $(#[$outer])*
        pub struct $name $(<$lt>)? {
            $(
                $(#[$inner])*
                $vis $field: $ty,
            )*
        }

        impl<'a> Serialize<'a> for $name $(<$lt>)? {
            fn serialized_len(&self) -> usize {
                let mut len = 0;
                $(
                    len += self.$field.serialized_len();
                )*
                len
            }

            fn serialize(&self, cursor: &mut [u8]) -> Result<usize, Error> {
                let mut index = 0;
                $(
                    index += self.$field.serialize(&mut cursor[index..])?;
                )*
                Ok(index)
            }

            fn deserialize(&mut self, mut cursor: Cursor<'a>) -> Result<Cursor<'a>, Error> {
                $(
                    cursor = self.$field.deserialize(cursor)?;
                )*
                Ok(cursor)
            }
        }
    };
}

/// An enum with a bevy of given variants.
macro_rules! num_enum {
    (
        $(#[$outer:meta])*
        pub enum $name:ident {
            $(
                $(#[$inner:meta])*
                $variant:ident = $value:expr,
            )*
        }
    ) => {
        $(#[$outer])*
        #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        // New codes may be added in the future.
        #[non_exhaustive]
        pub enum $name {
            $(
                $(#[$inner])*
                $variant = $value,
            )*
        }

        impl TryFrom<u16> for $name {
            type Error = InvalidCode;

            fn try_from(value: u16) -> Result<Self, Self::Error> {
                match value {
                    $(
                        $value => Ok($name::$variant),
                    )*
                    _ => Err(InvalidCode(value)),
                }
            }
        }

        impl From<$name> for u16 {
            fn from(value: $name) -> Self {
                value as u16
            }
        }

        impl<'a> Serialize<'a> for $name {
            fn serialized_len(&self) -> usize {
                mem::size_of::<u16>()
            }

            fn serialize(&self, cursor: &mut [u8]) -> Result<usize, Error> {
                let value: u16 = (*self).into();
                value.serialize(cursor)
            }

            fn deserialize(&mut self, cursor: Cursor<'a>) -> Result<Cursor<'a>, Error> {
                let mut value = 0;
                let cursor = value.deserialize(cursor)?;
                *self = value.try_into()?;
                Ok(cursor)
            }
        }
    };
}

/// An error that may occur while using the DNS protocol.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// We are trying to write to a buffer, but the buffer doesn't have enough space.
    ///
    /// This error can be fixed by increasing the size of the buffer.
    NotEnoughWriteSpace {
        /// The number of entries we tried to write.
        tried_to_write: NonZeroUsize,

        /// The number of entries that were available in the buffer.
        available: usize,

        /// The type of the buffer that we tried to write to.
        buffer_type: &'static str,
    },

    /// We attempted to read from a buffer, but we ran out of room before we could read the entire
    /// value.
    ///
    /// This error can be fixed by reading more bytes.
    NotEnoughReadBytes {
        /// The number of bytes we tried to read.
        tried_to_read: NonZeroUsize,

        /// The number of bytes that were available in the buffer.
        available: usize,
    },

    /// We tried to parse this value, but it was invalid.
    Parse {
        /// The name of the value we tried to parse.
        name: &'static str,
    },

    /// We tried to serialize a string longer than 256 bytes.
    NameTooLong(usize),

    /// We could not create a valid UTF-8 string from the bytes we read.
    InvalidUtf8(str::Utf8Error),

    /// We could not convert a raw number to a code.
    InvalidCode(InvalidCode),

    /// We do not support this many URL segments.
    TooManyUrlSegments(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotEnoughWriteSpace {
                tried_to_write,
                available,
                buffer_type,
            } => {
                write!(
                    f,
                    "not enough write space: tried to write {} entries to {} buffer, but only {} were available",
                    tried_to_write, buffer_type, available
                )
            }
            Error::NotEnoughReadBytes {
                tried_to_read,
                available,
            } => {
                write!(
                    f,
                    "not enough read bytes: tried to read {} bytes, but only {} were available",
                    tried_to_read, available
                )
            }
            Error::Parse { name } => {
                write!(f, "parse error: could not parse a {}", name)
            }
            Error::NameTooLong(len) => {
                write!(f, "name too long: name was {} bytes long", len)
            }
            Error::InvalidUtf8(err) => {
                write!(f, "invalid UTF-8: {}", err)
            }
            Error::TooManyUrlSegments(segments) => {
                write!(f, "too many URL segments: {} segments", segments)
            }
            Error::InvalidCode(err) => {
                write!(f, "{}", err)
            }
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::InvalidUtf8(err) => Some(err),
            Error::InvalidCode(err) => Some(err),
            _ => None,
        }
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Self {
        Error::InvalidUtf8(err)
    }
}

impl From<InvalidCode> for Error {
    fn from(err: InvalidCode) -> Self {
        Error::InvalidCode(err)
    }
}

/// The message for a DNS query.
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Message<'arrays, 'innards> {
    /// The header of the message.
    header: Header,

    /// The questions in the message.
    ///
    /// **Invariant:** This is always greater than or equal to `header.question_count`.
    questions: &'arrays mut [Question<'innards>],

    /// The answers in the message.
    ///
    /// **Invariant:** This is always greater than or equal to `header.answer_count`.
    answers: &'arrays mut [ResourceRecord<'innards>],

    /// The authorities in the message.
    ///
    /// **Invariant:** This is always greater than or equal to `header.authority_count`.
    authorities: &'arrays mut [ResourceRecord<'innards>],

    /// The additional records in the message.
    ///
    /// **Invariant:** This is always greater than or equal to `header.additional_count`.
    additional: &'arrays mut [ResourceRecord<'innards>],
}

impl fmt::Debug for Message<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("header", &self.header)
            .field("questions", &self.questions())
            .field("answers", &self.answers())
            .field("authorities", &self.authorities())
            .field("additional", &self.additional())
            .finish()
    }
}

impl<'arrays, 'innards> Message<'arrays, 'innards> {
    /// Create a new message from a set of buffers for each section.
    ///
    /// # Panics
    ///
    /// This function panics if the number of questions, answers, authorities, or additional records
    /// is greater than `u16::MAX`.
    pub fn new(
        id: u16,
        flags: Flags,
        questions: &'arrays mut [Question<'innards>],
        answers: &'arrays mut [ResourceRecord<'innards>],
        authorities: &'arrays mut [ResourceRecord<'innards>],
        additional: &'arrays mut [ResourceRecord<'innards>],
    ) -> Self {
        Self {
            header: Header {
                id,
                flags,
                question_count: questions.len().try_into().unwrap(),
                answer_count: answers.len().try_into().unwrap(),
                authority_count: authorities.len().try_into().unwrap(),
                additional_count: additional.len().try_into().unwrap(),
            },
            questions,
            answers,
            authorities,
            additional,
        }
    }

    /// Get the ID of this message.
    pub fn id(&self) -> u16 {
        self.header.id
    }

    /// Get a mutable reference to the ID of this message.
    pub fn id_mut(&mut self) -> &mut u16 {
        &mut self.header.id
    }

    /// Get the header of this message.
    pub fn header(&self) -> Header {
        self.header
    }

    /// Get the flags for this message.
    pub fn flags(&self) -> Flags {
        self.header.flags
    }

    /// Get a mutable reference to the flags for this message.
    pub fn flags_mut(&mut self) -> &mut Flags {
        &mut self.header.flags
    }

    /// Get the questions in this message.
    pub fn questions(&self) -> &[Question<'innards>] {
        &self.questions[..self.header.question_count as usize]
    }

    /// Get a mutable reference to the questions in this message.
    pub fn questions_mut(&mut self) -> &mut [Question<'innards>] {
        &mut self.questions[..self.header.question_count as usize]
    }

    /// Get the answers in this message.
    pub fn answers(&self) -> &[ResourceRecord<'innards>] {
        &self.answers[..self.header.answer_count as usize]
    }

    /// Get a mutable reference to the answers in this message.
    pub fn answers_mut(&mut self) -> &mut [ResourceRecord<'innards>] {
        &mut self.answers[..self.header.answer_count as usize]
    }

    /// Get the authorities in this message.
    pub fn authorities(&self) -> &[ResourceRecord<'innards>] {
        &self.authorities[..self.header.authority_count as usize]
    }

    /// Get a mutable reference to the authorities in this message.
    pub fn authorities_mut(&mut self) -> &mut [ResourceRecord<'innards>] {
        &mut self.authorities[..self.header.authority_count as usize]
    }

    /// Get the additional records in this message.
    pub fn additional(&self) -> &[ResourceRecord<'innards>] {
        &self.additional[..self.header.additional_count as usize]
    }

    /// Get a mutable reference to the additional records in this message.
    pub fn additional_mut(&mut self) -> &mut [ResourceRecord<'innards>] {
        &mut self.additional[..self.header.additional_count as usize]
    }

    /// Get the buffer space needed to serialize this message.
    pub fn space_needed(&self) -> usize {
        self.serialized_len()
    }

    /// Write this message to a buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// This function may raise [`Error::NameTooLong`] if a `Label` is too long to be serialized.
    ///
    /// # Panics
    ///
    /// This function panics if the buffer is not large enough to hold the serialized message. This
    /// panic can be avoided by ensuring the buffer contains at least [`space_needed`] bytes.
    pub fn write(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        self.serialize(buffer)
    }

    /// Read a message from a buffer.
    ///
    /// # Errors
    ///
    /// This function may raise one of the following errors:
    ///
    /// - [`Error::NotEnoughReadBytes`] if the buffer is not large enough to hold the entire structure.
    ///   You may need to read more data before calling this function again.
    /// - [`Error::NotEnoughWriteSpace`] if the buffers provided are not large enough to hold the
    ///   entire structure. You may need to allocate larger buffers before calling this function.
    /// - [`Error::InvalidUtf8`] if a domain name contains invalid UTF-8.
    /// - [`Error::NameTooLong`] if a domain name is too long to be deserialized.
    /// - [`Error::InvalidCode`] if a domain name contains an invalid label code.
    pub fn read(
        buffer: &'innards [u8],
        questions: &'arrays mut [Question<'innards>],
        answers: &'arrays mut [ResourceRecord<'innards>],
        authorities: &'arrays mut [ResourceRecord<'innards>],
        additional: &'arrays mut [ResourceRecord<'innards>],
    ) -> Result<Message<'arrays, 'innards>, Error> {
        // Create a message and cursor, then deserialize the message from the cursor.
        let mut message = Message::new(
            0,
            Flags::default(),
            questions,
            answers,
            authorities,
            additional,
        );
        let cursor = Cursor::new(buffer);

        message.deserialize(cursor)?;

        Ok(message)
    }
}

impl<'arrays, 'innards> Serialize<'innards> for Message<'arrays, 'innards> {
    fn serialized_len(&self) -> usize {
        iter::once(self.header.serialized_len())
            .chain(self.questions().iter().map(Serialize::serialized_len))
            .chain(self.answers().iter().map(Serialize::serialized_len))
            .chain(self.authorities().iter().map(Serialize::serialized_len))
            .chain(self.additional().iter().map(Serialize::serialized_len))
            .fold(0, |a, b| a.saturating_add(b))
    }

    fn serialize(&self, bytes: &mut [u8]) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.header.serialize(&mut bytes[offset..])?;
        for question in self.questions.iter() {
            offset += question.serialize(&mut bytes[offset..])?;
        }
        for answer in self.answers.iter() {
            offset += answer.serialize(&mut bytes[offset..])?;
        }
        for authority in self.authorities.iter() {
            offset += authority.serialize(&mut bytes[offset..])?;
        }
        for additional in self.additional.iter() {
            offset += additional.serialize(&mut bytes[offset..])?;
        }
        Ok(offset)
    }

    fn deserialize(&mut self, cursor: Cursor<'innards>) -> Result<Cursor<'innards>, Error> {
        /// Read a set of `T`, bounded by `count`.
        fn try_read_set<'a, T: Serialize<'a>>(
            mut cursor: Cursor<'a>,
            count: usize,
            items: &mut [T],
            name: &'static str,
        ) -> Result<Cursor<'a>, Error> {
            let len = items.len();

            if count == 0 {
                return Ok(cursor);
            }

            for i in 0..count {
                cursor = items
                    .get_mut(i)
                    .ok_or_else(|| Error::NotEnoughWriteSpace {
                        tried_to_write: NonZeroUsize::new(count).unwrap(),
                        available: len,
                        buffer_type: name,
                    })?
                    .deserialize(cursor)?;
            }

            Ok(cursor)
        }

        let cursor = self.header.deserialize(cursor)?;

        // If we're truncated, we can't read the rest of the message.
        if self.header.flags.truncated() {
            self.header.clear();
            return Ok(cursor);
        }

        let cursor = try_read_set(
            cursor,
            self.header.question_count as usize,
            self.questions,
            "Question",
        )?;
        let cursor = try_read_set(
            cursor,
            self.header.answer_count as usize,
            self.answers,
            "Answer",
        )?;
        let cursor = try_read_set(
            cursor,
            self.header.authority_count as usize,
            self.authorities,
            "Authority",
        )?;
        let cursor = try_read_set(
            cursor,
            self.header.additional_count as usize,
            self.additional,
            "Additional",
        )?;

        Ok(cursor)
    }
}

serialize! {
    /// The header for a DNS query.
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Header {
        /// The ID of this query.
        id: u16,

        /// The flags associated with this query.
        flags: Flags,

        /// The number of questions in this query.
        question_count: u16,

        /// The number of answers in this query.
        answer_count: u16,

        /// The number of authorities in this query.
        authority_count: u16,

        /// The number of additional records in this query.
        additional_count: u16,
    }
}

impl Header {
    fn clear(&mut self) {
        self.question_count = 0;
        self.answer_count = 0;
        self.authority_count = 0;
        self.additional_count = 0;
    }
}

serialize! {
    /// The question in a DNS query.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Question<'a> {
        /// The name of the question.
        name: Label<'a>,

        /// The type of the question.
        ty: ResourceType,

        /// The class of the question.
        class: u16,
    }
}

impl<'a> Question<'a> {
    /// Create a new question.
    pub fn new(label: impl Into<Label<'a>>, ty: ResourceType, class: u16) -> Self {
        Self {
            name: label.into(),
            ty,
            class,
        }
    }

    /// Get the name of the question.
    pub fn name(&self) -> Label<'a> {
        self.name
    }

    /// Get the type of the question.
    pub fn ty(&self) -> ResourceType {
        self.ty
    }

    /// Get the class of the question.
    pub fn class(&self) -> u16 {
        self.class
    }
}

serialize! {
    /// A resource record in a DNS query.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ResourceRecord<'a> {
        /// The name of the resource record.
        name: Label<'a>,

        /// The type of the resource record.
        ty: ResourceType,

        /// The class of the resource record.
        class: u16,

        /// The time-to-live of the resource record.
        ttl: u32,

        /// The data of the resource record.
        data: ResourceData<'a>,
    }
}

impl<'a> ResourceRecord<'a> {
    /// Create a new `ResourceRecord`.
    pub fn new(
        name: impl Into<Label<'a>>,
        ty: ResourceType,
        class: u16,
        ttl: u32,
        data: &'a [u8],
    ) -> Self {
        Self {
            name: name.into(),
            ty,
            class,
            ttl,
            data: data.into(),
        }
    }

    /// Get the name of the resource record.
    pub fn name(&self) -> Label<'a> {
        self.name
    }

    /// Get the type of the resource record.
    pub fn ty(&self) -> ResourceType {
        self.ty
    }

    /// Get the class of the resource record.
    pub fn class(&self) -> u16 {
        self.class
    }

    /// Get the time-to-live of the resource record.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Get the data of the resource record.
    pub fn data(&self) -> &'a [u8] {
        self.data.0
    }
}

/// The resource stored in a resource record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ResourceData<'a>(&'a [u8]);

impl<'a> From<&'a [u8]> for ResourceData<'a> {
    fn from(data: &'a [u8]) -> Self {
        ResourceData(data)
    }
}

impl<'a> Serialize<'a> for ResourceData<'a> {
    fn serialized_len(&self) -> usize {
        2 + self.0.len()
    }

    fn serialize(&self, bytes: &mut [u8]) -> Result<usize, Error> {
        let len = self.serialized_len();
        if bytes.len() < len {
            panic!("not enough bytes to serialize resource data");
        }

        // Write the length as a big-endian u16
        let [b1, b2] = (self.0.len() as u16).to_be_bytes();
        bytes[0] = b1;
        bytes[1] = b2;

        // Write the data
        bytes[2..len - 2].copy_from_slice(self.0);

        Ok(len)
    }

    fn deserialize(&mut self, cursor: Cursor<'a>) -> Result<Cursor<'a>, Error> {
        // Deserialize a u16 for the length
        let mut len = 0u16;
        let cursor = len.deserialize(cursor)?;

        if len == 0 {
            self.0 = &[];
            return Ok(cursor);
        }

        // Read in the data
        if cursor.len() < len as usize {
            return Err(Error::NotEnoughReadBytes {
                tried_to_read: NonZeroUsize::new(len as usize).unwrap(),
                available: cursor.len(),
            });
        }

        self.0 = &cursor.remaining()[..len as usize];
        cursor.advance(len as usize)
    }
}

/// The flags associated with a DNS message.
#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Flags(u16);

impl Flags {
    // Values used to manipulate the inside.
    const RAW_QR: u16 = 1 << 15;
    const RAW_OPCODE_SHIFT: u16 = 11;
    const RAW_OPCODE_MASK: u16 = 0b1111;
    const RAW_AA: u16 = 1 << 10;
    const RAW_TC: u16 = 1 << 9;
    const RAW_RD: u16 = 1 << 8;
    const RAW_RA: u16 = 1 << 7;
    const RAW_RCODE_SHIFT: u16 = 0;
    const RAW_RCODE_MASK: u16 = 0b1111;

    /// Create a new, empty set of flags.
    pub const fn new() -> Self {
        Self(0)
    }

    /// Use the standard set of flags for a DNS query.
    ///
    /// This is identical to `new()` but uses recursive querying.
    pub const fn standard_query() -> Self {
        Self(0x0100)
    }

    /// Get the query/response flag.
    pub fn qr(&self) -> MessageType {
        if self.0 & Self::RAW_QR != 0 {
            MessageType::Reply
        } else {
            MessageType::Query
        }
    }

    /// Set the message's query/response flag.
    pub fn set_qr(&mut self, qr: MessageType) -> &mut Self {
        if qr == MessageType::Reply {
            self.0 |= Self::RAW_QR;
        } else {
            self.0 &= !Self::RAW_QR;
        }

        self
    }

    /// Get the opcode.
    pub fn opcode(&self) -> Opcode {
        let raw = (self.0 >> Self::RAW_OPCODE_SHIFT) & Self::RAW_OPCODE_MASK;
        raw.try_into()
            .unwrap_or_else(|_| panic!("invalid opcode: {}", raw))
    }

    /// Set the opcode.
    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.0 |= (opcode as u16) << Self::RAW_OPCODE_SHIFT;
    }

    /// Get whether this message is authoritative.
    pub fn authoritative(&self) -> bool {
        self.0 & Self::RAW_AA != 0
    }

    /// Set whether this message is authoritative.
    pub fn set_authoritative(&mut self, authoritative: bool) -> &mut Self {
        if authoritative {
            self.0 |= Self::RAW_AA;
        } else {
            self.0 &= !Self::RAW_AA;
        }

        self
    }

    /// Get whether this message is truncated.
    pub fn truncated(&self) -> bool {
        self.0 & Self::RAW_TC != 0
    }

    /// Set whether this message is truncated.
    pub fn set_truncated(&mut self, truncated: bool) -> &mut Self {
        if truncated {
            self.0 |= Self::RAW_TC;
        } else {
            self.0 &= !Self::RAW_TC;
        }

        self
    }

    /// Get whether this message is recursive.
    pub fn recursive(&self) -> bool {
        self.0 & Self::RAW_RD != 0
    }

    /// Set whether this message is recursive.
    pub fn set_recursive(&mut self, recursive: bool) -> &mut Self {
        if recursive {
            self.0 |= Self::RAW_RD;
        } else {
            self.0 &= !Self::RAW_RD;
        }

        self
    }

    /// Get whether recursion is available for this message.
    pub fn recursion_available(&self) -> bool {
        self.0 & Self::RAW_RA != 0
    }

    /// Set whether recursion is available for this message.
    pub fn set_recursion_available(&mut self, recursion_available: bool) -> &mut Self {
        if recursion_available {
            self.0 |= Self::RAW_RA;
        } else {
            self.0 &= !Self::RAW_RA;
        }

        self
    }

    /// Get the response code.
    pub fn response_code(&self) -> ResponseCode {
        let raw = (self.0 >> Self::RAW_RCODE_SHIFT) & Self::RAW_RCODE_MASK;
        raw.try_into()
            .unwrap_or_else(|_| panic!("invalid response code: {}", raw))
    }

    /// Set the response code.
    pub fn set_response_code(&mut self, response_code: ResponseCode) -> &mut Self {
        self.0 |= (response_code as u16) << Self::RAW_RCODE_SHIFT;
        self
    }

    /// Get the raw value of these flags.
    pub fn raw(self) -> u16 {
        self.0
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();

        list.entry(&self.qr());
        list.entry(&self.opcode());

        if self.authoritative() {
            list.entry(&"authoritative");
        }

        if self.truncated() {
            list.entry(&"truncated");
        }

        if self.recursive() {
            list.entry(&"recursive");
        }

        if self.recursion_available() {
            list.entry(&"recursion available");
        }

        list.entry(&self.response_code());

        list.finish()
    }
}

impl<'a> Serialize<'a> for Flags {
    fn serialized_len(&self) -> usize {
        2
    }

    fn serialize(&self, buf: &mut [u8]) -> Result<usize, Error> {
        self.0.serialize(buf)
    }

    fn deserialize(&mut self, bytes: Cursor<'a>) -> Result<Cursor<'a>, Error> {
        u16::deserialize(&mut self.0, bytes)
    }
}

/// Whether a message is a query or a reply.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessageType {
    /// The message is a query.
    Query,

    /// The message is a reply.
    Reply,
}

num_enum! {
    /// The operation code for the query.
    pub enum Opcode {
        /// A standard query.
        Query = 0,

        /// A reverse query.
        IQuery = 1,

        /// A server status request.
        Status = 2,

        /// A notification of zone change.
        Notify = 4,

        /// A dynamic update.
        Update = 5,

        /// DSO query.
        Dso = 6,
    }
}

num_enum! {
    /// The response code for a query.
    pub enum ResponseCode {
        /// There was no error in the query.
        NoError = 0,

        /// The query was malformed.
        FormatError = 1,

        /// The server failed to fulfill the query.
        ServerFailure = 2,

        /// The name does not exist.
        NameError = 3,

        /// The query is not implemented.
        NotImplemented = 4,

        /// The query is refused.
        Refused = 5,

        /// The name exists, but the query type is not supported.
        YxDomain = 6,

        /// The name does not exist, but the query type is supported.
        YxRrSet = 7,

        /// The name exists, but the query type is not supported.
        NxRrSet = 8,

        /// The server is not authoritative for the zone.
        NotAuth = 9,

        /// The name does not exist in the zone.
        NotZone = 10,

        /// The DSO-TYPE is not supported.
        DsoTypeNi = 11,

        /// Bad OPT version.
        BadVers = 16,

        /// Key not recognized.
        BadKey = 17,

        /// Signature out of time window.
        BadTime = 18,

        /// Bad TKEY mode.
        BadMode = 19,

        /// Duplicate key name.
        BadName = 20,

        /// Algorithm not supported.
        BadAlg = 21,

        /// Bad truncation.
        BadTrunc = 22,

        /// Bad/missing server cookie.
        BadCookie = 23,
    }
}

num_enum! {
    /// The resource types that a question can ask for.
    pub enum ResourceType {
        /// Get the host's IPv4 address.
        A = 1,

        /// Get the authoritative name servers for a domain.
        NS = 2,

        /// Get the mail server for a domain.
        MD = 3,

        /// Get the mail forwarder for a domain.
        MF = 4,

        /// Get the canonical name for a domain.
        CName = 5,

        /// Get the start of authority record for a domain.
        Soa = 6,

        /// Get the mailbox for a domain.
        MB = 7,

        /// Get the mail group member for a domain.
        MG = 8,

        /// Get the mail rename domain for a domain.
        MR = 9,

        /// Get the null record for a domain.
        Null = 10,

        /// Get the well known services for a domain.
        Wks = 11,

        /// Get the domain pointer for a domain.
        Ptr = 12,

        /// Get the host information for a domain.
        HInfo = 13,

        /// Get the mailbox or mail list information for a domain.
        MInfo = 14,

        /// Get the mail exchange for a domain.
        MX = 15,

        /// Get the text for a domain.
        Txt = 16,

        /// Get the responsible person for a domain.
        RP = 17,

        /// Get the AFS database location for a domain.
        AfsDb = 18,

        /// Get the X.25 address for a domain.
        X25 = 19,

        /// Get the ISDN address for a domain.
        Isdn = 20,

        /// Get the router for a domain.
        Rt = 21,

        /// Get the NSAP address for a domain.
        NSap = 22,

        /// Get the reverse NSAP address for a domain.
        NSapPtr = 23,

        /// Get the security signature for a domain.
        Sig = 24,

        /// Get the key for a domain.
        Key = 25,

        /// Get the X.400 mail mapping for a domain.
        Px = 26,

        /// Get the geographical location for a domain.
        GPos = 27,

        /// Get the IPv6 address for a domain.
        AAAA = 28,

        /// Get the location for a domain.
        Loc = 29,

        /// Get the next domain name in a zone.
        Nxt = 30,

        /// Get the endpoint identifier for a domain.
        EId = 31,

        /// Get the Nimrod locator for a domain.
        NimLoc = 32,

        /// Get the server selection for a domain.
        Srv = 33,

        /// Get the ATM address for a domain.
        AtmA = 34,

        /// Get the naming authority pointer for a domain.
        NAPtr = 35,

        /// Get the key exchange for a domain.
        Kx = 36,

        /// Get the certificate for a domain.
        Cert = 37,

        /// Get the IPv6 address for a domain.
        ///
        /// This is obsolete; use `AAAA` instead.
        A6 = 38,

        /// Get the DNAME for a domain.
        DName = 39,

        /// Get the sink for a domain.
        Sink = 40,

        /// Get the OPT for a domain.
        Opt = 41,

        /// Get the address prefix list for a domain.
        ApL = 42,

        /// Get the delegation signer for a domain.
        DS = 43,

        /// Get the SSH key fingerprint for a domain.
        SshFp = 44,

        /// Get the IPSEC key for a domain.
        IpSecKey = 45,

        /// Get the resource record signature for a domain.
        RRSig = 46,

        /// Get the next secure record for a domain.
        NSEC = 47,

        /// Get the DNSKEY for a domain.
        DNSKey = 48,

        /// Get the DHCID for a domain.
        DHCID = 49,

        /// Get the NSEC3 for a domain.
        NSEC3 = 50,

        /// Get the NSEC3 parameters for a domain.
        NSEC3Param = 51,

        /// Get the TLSA for a domain.
        TLSA = 52,

        /// Get the S/MIME certificate association for a domain.
        SMimeA = 53,

        /// Get the host information for a domain.
        HIP = 55,

        /// Get the NINFO for a domain.
        NInfo = 56,

        /// Get the RKEY for a domain.
        RKey = 57,

        /// Get the trust anchor link for a domain.
        TALink = 58,

        /// Get the child DS for a domain.
        CDS = 59,

        /// Get the DNSKEY for a domain.
        CDNSKey = 60,

        /// Get the OpenPGP key for a domain.
        OpenPGPKey = 61,

        /// Get the Child-to-Parent Synchronization for a domain.
        CSync = 62,

        /// Get the Zone Data Message for a domain.
        ZoneMD = 63,

        /// Get the General Purpose Service Binding for a domain.
        Svcb = 64,

        /// Get the HTTP Service Binding for a domain.
        Https = 65,

        /// Get the Sender Policy Framework for a domain.
        Spf = 99,

        /// Get the UINFO for a domain.
        UInfo = 100,

        /// Get the UID for a domain.
        UID = 101,

        /// Get the GID for a domain.
        GID = 102,

        /// Get the UNSPEC for a domain.
        Unspec = 103,

        /// Get the NID for a domain.
        NID = 104,

        /// Get the L32 for a domain.
        L32 = 105,

        /// Get the L64 for a domain.
        L64 = 106,

        /// Get the LP for a domain.
        LP = 107,

        /// Get the EUI48 for a domain.
        EUI48 = 108,

        /// Get the EUI64 for a domain.
        EUI64 = 109,

        /// Get the transaction key for a domain.
        TKey = 249,

        /// Get the transaction signature for a domain.
        TSig = 250,

        /// Get the incremental transfer for a domain.
        Ixfr = 251,

        /// Get the transfer of an entire zone for a domain.
        Axfr = 252,

        /// Get the mailbox-related records for a domain.
        MailB = 253,

        /// Get the mail agent RRs for a domain.
        ///
        /// This is obsolete; use `MX` instead.
        MailA = 254,

        /// Get the wildcard match for a domain.
        Wildcard = 255,

        /// Get the URI for a domain.
        Uri = 256,

        /// Get the certification authority authorization for a domain.
        Caa = 257,

        /// Get the application visibility and control for a domain.
        Avc = 258,

        /// Get the digital object architecture for a domain.
        Doa = 259,

        /// Get the automatic network discovery for a domain.
        Amtrelay = 260,

        /// Get the DNSSEC trust authorities for a domain.
        TA = 32768,

        /// Get the DNSSEC lookaside validation for a domain.
        DLV = 32769,
    }
}

impl Default for ResourceType {
    fn default() -> Self {
        Self::A
    }
}

/// The given value is not a valid code.
#[derive(Debug, Clone)]
pub struct InvalidCode(u16);

impl InvalidCode {
    /// Get the invalid code.
    pub fn code(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for InvalidCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid code: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl StdError for InvalidCode {}
