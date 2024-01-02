use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use zeroize::ZeroizeOnDrop;

/// Generic buffer type that hold sensitive/secret data. All the bytes
/// are zeroized (zeroed out) whenever the value is dropped.
///
/// This type should be used anytime you need a `Vec<u8>`/buffer that holds
/// sensitive or secret information.
///
/// Note: We purposely restrict the API to minimize accidental leaking and
/// copying of data. Think carefully before adding new methods!
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, ZeroizeOnDrop)]
pub struct SecureBuffer {
    buffer: Vec<u8>,
}

impl Debug for SecureBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBuffer")
            .field("buffer", &"REDACTED")
            .finish()
    }
}

impl SecureBuffer {
    /// Create a new buffer with the specified, pre-allocated space.
    pub fn new(capacity: usize) -> SecureBuffer {
        SecureBuffer {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Convert an existing `buffer` to a `SecureBuffer` by taking ownership of
    /// its data; this ensures no copies are made.
    pub fn from_vec(buffer: Vec<u8>) -> SecureBuffer {
        SecureBuffer { buffer }
    }

    /// Note: this function does not return a `&mut [u8]`! We purposely return a
    /// `&mut Vec<u8>`. As the former type causes issues with the `TcpStream::try_read_buf`
    /// method: try_read_buf only ever returns `Ok(0)`. The cause of this is likely a bug on
    /// that library.
    pub fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.buffer
    }

    /// Length and capacity of a vector are not the same thing. Use
    /// this constructor when you are going to work with a slice of
    /// the buffer, for example: buf[recv_bytes..len]. If we create
    /// a Vec with a capacity but don't fill it with any data, and
    /// then index the slice, this will result in a runtime panic
    /// trying to access the nth element of a zero length vector.
    pub fn with_len(len: usize) -> SecureBuffer {
        SecureBuffer {
            buffer: vec![0; len],
        }
    }
}

impl AsRef<[u8]> for SecureBuffer {
    /// Access underlying bytes of this secure buffer.
    ///
    /// Warning: Think very carefully before cloning the underlying `u8` slice, as there is
    /// no guarantee they are getting zeroized once you clone them like this.
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

/// Wrapper around a [`String`] that hold sensitive/secret data. All the bytes
/// are zeroized (zeroed out) whenever the value is dropped.
///
/// This type should be used anytime you need a `String` that holds
/// sensitive or secret information.
///
/// Note: We purposely restrict the API to minimize accidental leaking and
/// copying of data. Think carefully before adding new methods!
#[derive(Default, Clone, Deserialize, Eq, PartialEq, Serialize, ZeroizeOnDrop)]
pub struct SecureString {
    string: String,
}

impl Debug for SecureString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureString")
            .field("string", &"REDACTED")
            .finish()
    }
}

impl SecureString {
    /// Useful function for converting our test KMS_ARN into a SecureString. This should only be used
    /// in non-production code! As of the writing of this doc-string, there is no reason to use this
    /// in prod code.
    pub fn from_str_slice(string: &str) -> SecureString {
        SecureString {
            string: string.to_string(),
        }
    }

    /// Convert an existing `string` to a `SecureString` by taking ownership of
    /// its data; this ensures no copies are made.
    pub fn from_string(string: String) -> SecureString {
        SecureString { string }
    }

    pub fn is_empty(&self) -> bool {
        self.string.is_empty()
    }

    pub fn len(&self) -> usize {
        self.string.len()
    }
}

impl AsRef<str> for SecureString {
    /// Access underlying bytes of this secure string.
    ///
    /// Warning: Think very carefully before cloning the underlying `&str`, as there is
    /// no guarantee they are getting zeroized once you clone them like this.
    fn as_ref(&self) -> &str {
        &self.string
    }
}
