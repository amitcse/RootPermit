//! A deliberately small RFC 8949 deterministic-CBOR profile.
//!
//! It accepts only the data model needed by RootPermit schemas and validates
//! canonical wire representation while parsing.  In particular, decoding then
//! re-encoding is **not** used as a canonicality check: that approach can hide
//! duplicate map keys and alternate encodings before the schema sees them.

use core::cmp::Ordering;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborLimits {
    pub max_message_bytes: usize,
    pub max_nesting: usize,
    pub max_map_entries: usize,
    pub max_array_entries: usize,
    pub max_byte_string_bytes: usize,
    pub max_text_string_bytes: usize,
}

impl Default for CborLimits {
    fn default() -> Self {
        Self {
            // A frozen plan can contain a substantial dependency graph, but no
            // individual protocol object should grow without an explicit limit.
            max_message_bytes: 1_048_576,
            max_nesting: 16,
            max_map_entries: 128,
            max_array_entries: 16_384,
            max_byte_string_bytes: 65_536,
            max_text_string_bytes: 16_384,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecodeError {
    #[error("CBOR message exceeds its configured byte limit")]
    MessageTooLarge,
    #[error("unexpected end of CBOR input")]
    UnexpectedEof,
    #[error("CBOR uses an unsupported major type or simple value")]
    UnsupportedType,
    #[error("indefinite-length CBOR is forbidden")]
    IndefiniteLength,
    #[error("CBOR integer or length is not minimally encoded")]
    NonCanonicalInteger,
    #[error("CBOR map keys are not in deterministic order or are duplicated")]
    NonCanonicalMapOrder,
    #[error("CBOR UTF-8 text is invalid")]
    InvalidUtf8,
    #[error("CBOR nesting exceeds the configured limit")]
    NestingTooDeep,
    #[error("CBOR {kind} exceeds its configured limit")]
    CollectionTooLarge { kind: &'static str },
    #[error("CBOR has trailing bytes")]
    TrailingBytes,
    #[error("CBOR value does not fit the supported signed integer range")]
    IntegerOutOfRange,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EncodeError {
    #[error("a CBOR map contains duplicate deterministic keys")]
    DuplicateMapKey,
    #[error("the value exceeds the RootPermit CBOR profile limits: {0}")]
    Profile(DecodeError),
    #[error("a CBOR length cannot be represented as an unsigned 64-bit integer")]
    LengthOutOfRange,
    #[error("a CBOR negative integer cannot be represented as an unsigned 64-bit argument")]
    IntegerOutOfRange,
}

/// Decodes one fully-consumed deterministic-CBOR value.
pub fn decode(input: &[u8]) -> Result<CborValue, DecodeError> {
    decode_with_limits(input, CborLimits::default())
}

pub fn decode_with_limits(input: &[u8], limits: CborLimits) -> Result<CborValue, DecodeError> {
    if input.len() > limits.max_message_bytes {
        return Err(DecodeError::MessageTooLarge);
    }
    let mut parser = Parser { input, offset: 0, limits };
    let value = parser.value(0)?;
    if parser.offset != input.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(value)
}

/// Encodes a value according to the RFC 8949 core deterministic profile.
///
/// Callers should use typed schema encoders for protocol payloads.  This helper
/// remains useful for encoding validated nested projections and vector fixtures.
pub fn encode(value: &CborValue) -> Result<Vec<u8>, EncodeError> {
    let mut output = Vec::new();
    encode_into(value, &mut output)?;
    // Encoding is also constrained by the same profile bounds as decoding, so
    // an in-memory value cannot produce a valid-but-unbounded wire object.
    decode(&output).map_err(EncodeError::Profile)?;
    Ok(output)
}

fn encode_into(value: &CborValue, output: &mut Vec<u8>) -> Result<(), EncodeError> {
    match value {
        CborValue::Unsigned(value) => write_head(0, *value, output),
        CborValue::Negative(value) => {
            let encoded = u64::try_from(-1_i128 - i128::from(*value))
                .map_err(|_| EncodeError::IntegerOutOfRange)?;
            write_head(1, encoded, output);
        }
        CborValue::Bytes(value) => {
            write_head(2, length_u64(value.len())?, output);
            output.extend_from_slice(value);
        }
        CborValue::Text(value) => {
            write_head(3, length_u64(value.len())?, output);
            output.extend_from_slice(value.as_bytes());
        }
        CborValue::Array(values) => {
            write_head(4, length_u64(values.len())?, output);
            for value in values {
                encode_into(value, output)?;
            }
        }
        CborValue::Map(entries) => {
            let mut entries: Vec<_> = entries
                .iter()
                .map(|(key, value)| Ok((key, value, encode(key)?)))
                .collect::<Result<_, EncodeError>>()?;
            entries.sort_by(|left, right| {
                left.2.len().cmp(&right.2.len()).then_with(|| left.2.cmp(&right.2))
            });
            for pair in entries.windows(2) {
                if pair[0].2 == pair[1].2 {
                    return Err(EncodeError::DuplicateMapKey);
                }
            }
            write_head(5, length_u64(entries.len())?, output);
            for (key, value, _) in entries {
                encode_into(key, output)?;
                encode_into(value, output)?;
            }
        }
        CborValue::Bool(false) => output.push(0xf4),
        CborValue::Bool(true) => output.push(0xf5),
        CborValue::Null => output.push(0xf6),
    }
    Ok(())
}

fn write_head(major: u8, value: u64, output: &mut Vec<u8>) {
    debug_assert!(major <= 7);
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => output.push((major << 5) | bytes[7]),
        24..=0xff => output.extend_from_slice(&[(major << 5) | 24, bytes[7]]),
        0x100..=0xffff => {
            output.push((major << 5) | 25);
            output.extend_from_slice(&bytes[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            output.push((major << 5) | 26);
            output.extend_from_slice(&bytes[4..]);
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend_from_slice(&bytes);
        }
    }
}

fn length_u64(value: usize) -> Result<u64, EncodeError> {
    u64::try_from(value).map_err(|_| EncodeError::LengthOutOfRange)
}

struct Parser<'a> {
    input: &'a [u8],
    offset: usize,
    limits: CborLimits,
}

impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Result<CborValue, DecodeError> {
        if depth > self.limits.max_nesting {
            return Err(DecodeError::NestingTooDeep);
        }
        let initial = self.take_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if additional == 31 {
            return Err(DecodeError::IndefiniteLength);
        }
        match major {
            0 => Ok(CborValue::Unsigned(self.argument(additional)?)),
            1 => {
                let argument = self.argument(additional)?;
                let value = -1_i128 - i128::from(argument);
                let value = i64::try_from(value).map_err(|_| DecodeError::IntegerOutOfRange)?;
                Ok(CborValue::Negative(value))
            }
            2 => {
                let length = self.length(additional, self.limits.max_byte_string_bytes, "byte string")?;
                Ok(CborValue::Bytes(self.take(length)?.to_vec()))
            }
            3 => {
                let length = self.length(additional, self.limits.max_text_string_bytes, "text string")?;
                let text = core::str::from_utf8(self.take(length)?).map_err(|_| DecodeError::InvalidUtf8)?;
                Ok(CborValue::Text(text.to_owned()))
            }
            4 => {
                let length = self.length(additional, self.limits.max_array_entries, "array")?;
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    values.push(self.value(depth + 1)?);
                }
                Ok(CborValue::Array(values))
            }
            5 => {
                let length = self.length(additional, self.limits.max_map_entries, "map")?;
                let mut entries = Vec::with_capacity(length);
                let mut previous_key: Option<Vec<u8>> = None;
                for _ in 0..length {
                    let key_start = self.offset;
                    let key = self.value(depth + 1)?;
                    let key_bytes = self.input[key_start..self.offset].to_vec();
                    if let Some(previous) = &previous_key {
                        let ordering = previous.len().cmp(&key_bytes.len()).then_with(|| previous.cmp(&key_bytes));
                        if ordering != Ordering::Less {
                            return Err(DecodeError::NonCanonicalMapOrder);
                        }
                    }
                    previous_key = Some(key_bytes);
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(CborValue::Map(entries))
            }
            7 => match additional {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                _ => Err(DecodeError::UnsupportedType),
            },
            _ => Err(DecodeError::UnsupportedType),
        }
    }

    fn argument(&mut self, additional: u8) -> Result<u64, DecodeError> {
        let (value, width) = match additional {
            value @ 0..=23 => (u64::from(value), 0),
            24 => (u64::from(self.take_byte()?), 1),
            25 => (u64::from(u16::from_be_bytes(self.take_array()?)), 2),
            26 => (u64::from(u32::from_be_bytes(self.take_array()?)), 4),
            27 => (u64::from_be_bytes(self.take_array()?), 8),
            _ => return Err(DecodeError::IndefiniteLength),
        };
        let canonical = match width {
            0 => value <= 23,
            1 => value >= 24,
            2 => value > u64::from(u8::MAX),
            4 => value > u64::from(u16::MAX),
            8 => value > u64::from(u32::MAX),
            _ => false,
        };
        if canonical { Ok(value) } else { Err(DecodeError::NonCanonicalInteger) }
    }

    fn length(&mut self, additional: u8, max: usize, kind: &'static str) -> Result<usize, DecodeError> {
        let length = usize::try_from(self.argument(additional)?).map_err(|_| DecodeError::CollectionTooLarge { kind })?;
        if length > max {
            return Err(DecodeError::CollectionTooLarge { kind });
        }
        Ok(length)
    }

    fn take_byte(&mut self) -> Result<u8, DecodeError> {
        let byte = *self.input.get(self.offset).ok_or(DecodeError::UnexpectedEof)?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&[u8], DecodeError> {
        let end = self.offset.checked_add(length).ok_or(DecodeError::UnexpectedEof)?;
        let slice = self.input.get(self.offset..end).ok_or(DecodeError::UnexpectedEof)?;
        self.offset = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?.try_into().map_err(|_| DecodeError::UnexpectedEof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_map_keys_by_encoded_length_then_bytes() {
        let map = CborValue::Map(vec![
            (CborValue::Text("z".into()), CborValue::Null),
            (CborValue::Unsigned(24), CborValue::Null),
            (CborValue::Unsigned(1), CborValue::Null),
        ]);
        assert_eq!(encode(&map).unwrap(), vec![0xa3, 0x01, 0xf6, 0x18, 0x18, 0xf6, 0x61, b'z', 0xf6]);
    }

    #[test]
    fn rejects_noncanonical_and_unsafe_forms() {
        assert_eq!(decode(&[0x18, 0x01]), Err(DecodeError::NonCanonicalInteger));
        assert_eq!(decode(&[0x5f, 0xff]), Err(DecodeError::IndefiniteLength));
        assert_eq!(decode(&[0xa2, 0x01, 0xf6, 0x01, 0xf6]), Err(DecodeError::NonCanonicalMapOrder));
        assert_eq!(decode(&[0xf6, 0xf6]), Err(DecodeError::TrailingBytes));
    }
}
