//! A serializer/deserializer compatible with the DNS wire format.
//!
//! Various notes about the wire format:
//!
//! - All integers are in big endian format.
//! - All strings are length-prefixed.
//! - Names consist of a series of labels, each prefixed with a length byte.
//! - Names end with a zero byte.
//! - Names are compressed by using a pointer to a previous name.
//! - This means that we need access to the entire buffer.

use super::Error;

use core::convert::TryInto;
use core::fmt;
use core::hash;
use core::iter;
use core::mem;
use core::num::NonZeroUsize;

use memchr::Memchr;

/// An object that is able to be serialized to or deserialized from a series of bytes.
pub(crate) trait Serialize<'a> {
    /// The number of bytes needed to serialize this object.
    fn serialized_len(&self) -> usize;

    /// Serialize this object into a series of bytes.
    fn serialize(&self, bytes: &mut [u8]) -> Result<usize, Error>;

    /// Deserialize this object from a series of bytes.
    fn deserialize(&mut self, cursor: Cursor<'a>) -> Result<Cursor<'a>, Error>;
}

/// A cursor into a series of bytes.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Cursor<'a> {
    /// The bytes being read.
    bytes: &'a [u8],

    /// The index into the bytes that we've read so far.
    cursor: usize,
}

impl<'a> Cursor<'a> {
    /// Create a new cursor from a series of bytes.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    /// Get the original bytes that this cursor was created from.
    pub(crate) fn original(&self) -> &'a [u8] {
        self.bytes
    }

    /// Get the slice of remaining bytes.
    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.cursor..]
    }

    /// Get the length of the slice of remaining bytes.
    pub(crate) fn len(&self) -> usize {
        self.bytes.len() - self.cursor
    }

    /// Get a new cursor at the given absolute position.
    pub(crate) fn at(&self, pos: usize) -> Self {
        Self {
            bytes: self.bytes,
            cursor: pos,
        }
    }

    /// Advance the cursor by the given number of bytes.
    pub(crate) fn advance(mut self, n: usize) -> Result<Self, Error> {
        if n == 0 {
            return Ok(self);
        }

        if self.cursor + n > self.bytes.len() {
            return Err(Error::NotEnoughReadBytes {
                tried_to_read: NonZeroUsize::new(self.cursor.saturating_add(n)).unwrap(),
                available: self.bytes.len(),
            });
        }

        self.cursor += n;
        Ok(self)
    }

    /// Error for when a read of `n` bytes failed.
    fn read_error(&self, n: usize) -> Error {
        Error::NotEnoughReadBytes {
            tried_to_read: NonZeroUsize::new(self.cursor.saturating_add(n)).unwrap(),
            available: self.bytes.len(),
        }
    }
}

impl<'a> Serialize<'a> for () {
    fn serialized_len(&self) -> usize {
        0
    }

    fn serialize(&self, _bytes: &mut [u8]) -> Result<usize, Error> {
        Ok(0)
    }

    fn deserialize(&mut self, bytes: Cursor<'a>) -> Result<Cursor<'a>, Error> {
        Ok(bytes)
    }
}

/// A DNS name.
#[derive(Clone, Copy)]
pub struct Label<'a> {
    repr: Repr<'a>,
}

/// Internal representation of a DNS name.
#[derive(Clone, Copy)]
enum Repr<'a> {
    /// The name is represented by its range of bytes in the initial buffer.
    ///
    /// It is lazily parsed into labels when needed.
    Bytes {
        /// The original buffer, in totality, that this name was parsed from.
        original: &'a [u8],

        /// The starting position of this name in the original buffer.
        start: usize,

        /// The ending position of this name in the original buffer.
        end: usize,
    },

    /// The label will be the parsed version of this string.
    String {
        /// The string representation of the label.
        string: &'a str,
    },
}

impl Default for Label<'_> {
    fn default() -> Self {
        // An empty label.
        Self {
            repr: Repr::Bytes {
                original: &[0],
                start: 0,
                end: 1,
            },
        }
    }
}

impl<'a, 'b> PartialEq<Label<'a>> for Label<'b> {
    fn eq(&self, other: &Label<'a>) -> bool {
        self.segments().eq(other.segments())
    }
}

impl Eq for Label<'_> {}

impl<'a, 'b> PartialOrd<Label<'a>> for Label<'b> {
    fn partial_cmp(&self, other: &Label<'a>) -> Option<core::cmp::Ordering> {
        self.segments().partial_cmp(other.segments())
    }
}

impl Ord for Label<'_> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.segments().cmp(other.segments())
    }
}

impl hash::Hash for Label<'_> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for segment in self.segments() {
            segment.hash(state);
        }
    }
}

impl<'a> Label<'a> {
    /// Get an iterator over the label segments in this name.
    pub fn segments(&self) -> impl Iterator<Item = LabelSegment<'a>> {
        match self.repr {
            Repr::Bytes {
                original, start, ..
            } => Either::A(parse_bytes(original, start)),
            Repr::String { string } => Either::B(parse_string(string)),
        }
    }

    /// Get an iterator over the strings making up this name.
    pub fn names(&self) -> impl Iterator<Item = Result<&'a str, &'a [u8]>> {
        match self.repr {
            Repr::String { string } => {
                // Guaranteed to have no pointers.
                Either::A(parse_string(string).filter_map(|seg| seg.as_str().map(Ok)))
            }
            Repr::Bytes {
                original, start, ..
            } => {
                // We may have to deal with pointers. Parse it manually.
                let mut cursor = Cursor {
                    bytes: original,
                    cursor: start,
                };

                Either::B(iter::from_fn(move || {
                    loop {
                        let mut ls: LabelSegment<'_> = LabelSegment::Empty;
                        cursor = ls.deserialize(cursor).ok()?;

                        // TODO: Handle the case where utf-8 errors out.
                        match ls {
                            LabelSegment::Empty => return None,
                            LabelSegment::Pointer(pos) => {
                                // Change to another location.
                                cursor = cursor.at(pos.into());
                            }
                            LabelSegment::String(label) => return Some(Ok(label)),
                        }
                    }
                }))
            }
        }
    }
}

impl<'a> From<&'a str> for Label<'a> {
    fn from(string: &'a str) -> Self {
        Self {
            repr: Repr::String { string },
        }
    }
}

impl fmt::Debug for Label<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct LabelFmt<'a>(&'a Label<'a>);

        impl fmt::Debug for LabelFmt<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self.0, f)
            }
        }

        f.debug_tuple("Label").field(&LabelFmt(self)).finish()
    }
}

impl fmt::Display for Label<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.names().enumerate().try_for_each(|(i, name)| {
            if i > 0 {
                f.write_str(".")?;
            }

            match name {
                Ok(name) => f.write_str(name),
                Err(_) => f.write_str("???"),
            }
        })
    }
}

impl<'a> Serialize<'a> for Label<'a> {
    fn serialized_len(&self) -> usize {
        if let Repr::Bytes { start, end, .. } = self.repr {
            return end - start;
        }

        self.segments()
            .map(|item| item.serialized_len())
            .fold(0, |a, b| a.saturating_add(b))
    }

    fn serialize(&self, bytes: &mut [u8]) -> Result<usize, Error> {
        // Fast path: just copy our bytes.
        if let Repr::Bytes {
            original,
            start,
            end,
        } = self.repr
        {
            bytes[..end - start].copy_from_slice(&original[start..end]);
            return Ok(end - start);
        }

        self.segments().try_fold(0, |mut offset, item| {
            let len = item.serialize(&mut bytes[offset..])?;
            offset += len;
            Ok(offset)
        })
    }

    fn deserialize(&mut self, cursor: Cursor<'a>) -> Result<Cursor<'a>, Error> {
        let original = cursor.original();
        let start = cursor.cursor;

        // Figure out where the end is.
        let mut end = start;
        loop {
            if original[end] == 0 {
                end += 1;
                break;
            }

            let len = original[end] as usize;
            end += len + 1;
        }

        self.repr = Repr::Bytes {
            original,
            start,
            end,
        };
        cursor.advance(end - start)
    }
}

/// Parse a set of bytes as a DNS name.
fn parse_bytes(bytes: &[u8], position: usize) -> impl Iterator<Item = LabelSegment<'_>> + '_ {
    let mut cursor = Cursor {
        bytes,
        cursor: position,
    };
    let mut keep_going = true;

    iter::from_fn(move || {
        if !keep_going {
            return None;
        }

        let mut segment = LabelSegment::Empty;
        cursor = segment.deserialize(cursor).ok()?;

        if !matches!(segment, LabelSegment::String(_)) {
            keep_going = false;
        }

        Some(segment)
    })
}

/// Parse a string as a DNS name.
fn parse_string(str: &str) -> impl Iterator<Item = LabelSegment<'_>> + '_ {
    let dot = Memchr::new(b'.', str.as_bytes());
    let mut last_index = 0;

    dot.filter_map(move |index| {
        let item = &str[last_index..index];
        last_index = index.saturating_add(1);

        if item.is_empty() {
            None
        } else {
            Some(LabelSegment::String(item))
        }
    })
    .chain(Some(LabelSegment::Empty))
}

/// A DNS-compatible label segment.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LabelSegment<'a> {
    /// The empty terminator.
    Empty,

    /// A string label.
    String(&'a str),

    /// A pointer to a previous name.
    Pointer(u16),
}

const MAX_STR_LEN: usize = !PTR_MASK as usize;
const PTR_MASK: u8 = 0b1100_0000;

impl<'a> LabelSegment<'a> {
    fn as_str(&self) -> Option<&'a str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
}

impl Default for LabelSegment<'_> {
    fn default() -> Self {
        Self::Empty
    }
}

impl<'a> Serialize<'a> for LabelSegment<'a> {
    fn serialized_len(&self) -> usize {
        match self {
            Self::Empty => 1,
            Self::Pointer(_) => 2,
            Self::String(s) => 1 + s.len(),
        }
    }

    fn serialize(&self, bytes: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Empty => {
                // An empty label segment is just a zero byte.
                bytes[0] = 0;
                Ok(1)
            }
            Self::Pointer(ptr) => {
                // Apply the pointer mask to the first byte.
                let [mut b1, b2] = ptr.to_be_bytes();
                b1 |= PTR_MASK;
                bytes[0] = b1;
                bytes[1] = b2;
                Ok(2)
            }
            Self::String(s) => {
                // First, serialize the length byte.
                let len = s.len();

                if len > MAX_STR_LEN {
                    return Err(Error::NameTooLong(len));
                }

                if len > bytes.len() {
                    panic!("not enough bytes to serialize string");
                }

                bytes[0] = len as u8;
                bytes[1..=len].copy_from_slice(s.as_bytes());
                Ok(len + 1)
            }
        }
    }

    fn deserialize(&mut self, cursor: Cursor<'a>) -> Result<Cursor<'a>, Error> {
        // The type is determined by the first byte.
        let b1 = *cursor
            .remaining()
            .first()
            .ok_or_else(|| cursor.read_error(1))?;

        if b1 == 0 {
            // An empty label segment is just a zero byte.
            *self = Self::Empty;
            cursor.advance(1)
        } else if b1 & PTR_MASK == PTR_MASK {
            // A pointer is a 2-byte value with the pointer mask applied to the first byte.
            let [b1, b2]: [u8; 2] = cursor.remaining()[..2]
                .try_into()
                .map_err(|_| cursor.read_error(2))?;
            let ptr = u16::from_be_bytes([b1 & !PTR_MASK, b2]);
            *self = Self::Pointer(ptr);
            cursor.advance(2)
        } else {
            // A string label is a length byte followed by the string.
            let len = b1 as usize;

            if len > MAX_STR_LEN {
                return Err(Error::NameTooLong(len));
            }

            // Parse the string's bytes.
            let bytes = cursor.remaining()[1..=len]
                .try_into()
                .map_err(|_| cursor.read_error(len + 1))?;

            // Parse as UTF8
            let s = core::str::from_utf8(bytes)?;
            *self = Self::String(s);
            cursor.advance(len + 1)
        }
    }
}

macro_rules! serialize_num {
    ($($num_ty: ident),*) => {
        $(
            impl<'a> Serialize<'a> for $num_ty {
                fn serialized_len(&self) -> usize {
                    mem::size_of::<$num_ty>()
                }

                fn serialize(&self, bytes: &mut [u8]) -> Result<usize, Error> {
                    if bytes.len() < mem::size_of::<$num_ty>() {
                        panic!("Not enough space to serialize a {}", stringify!($num_ty));
                    }

                    let value = (*self).to_be_bytes();
                    bytes[..mem::size_of::<$num_ty>()].copy_from_slice(&value);

                    Ok(mem::size_of::<$num_ty>())
                }

                fn deserialize(&mut self, bytes: Cursor<'a>) -> Result<Cursor<'a>, Error> {
                    if bytes.len() < mem::size_of::<$num_ty>() {
                        return Err(bytes.read_error(mem::size_of::<$num_ty>()));
                    }

                    let mut value = [0; mem::size_of::<$num_ty>()];
                    value.copy_from_slice(&bytes.remaining()[..mem::size_of::<$num_ty>()]);
                    *self = $num_ty::from_be_bytes(value);

                    bytes.advance(mem::size_of::<$num_ty>())
                }
            }
        )*
    }
}

serialize_num! {
    u8, u16, u32, u64,
    i8, i16, i32, i64
}

/// One iterator or another.
enum Either<A, B> {
    A(A),
    B(B),
}

impl<A: Iterator, Other: Iterator<Item = A::Item>> Iterator for Either<A, Other> {
    type Item = A::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Either::A(a) => a.next(),
            Either::B(b) => b.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Either::A(a) => a.size_hint(),
            Either::B(b) => b.size_hint(),
        }
    }

    fn fold<B, F>(self, init: B, f: F) -> B
    where
        Self: Sized,
        F: FnMut(B, Self::Item) -> B,
    {
        match self {
            Either::A(a) => a.fold(init, f),
            Either::B(b) => b.fold(init, f),
        }
    }
}
