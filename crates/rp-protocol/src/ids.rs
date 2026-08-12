use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use core::fmt;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentifierError {
    #[error("{name} must contain exactly {expected} bytes, got {actual}")]
    WrongLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
}

macro_rules! fixed_bytes {
    ($name:ident, $len:expr, $label:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = IdentifierError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                let bytes: [u8; $len] =
                    value.try_into().map_err(|_| IdentifierError::WrongLength {
                        name: $label,
                        expected: $len,
                        actual: value.len(),
                    })?;
                Ok(Self(bytes))
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&URL_SAFE_NO_PAD.encode(self.0))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
            }
        }
    };
}

fixed_bytes!(RequestId, 16, "request ID");
fixed_bytes!(ReceiptId, 16, "receipt ID");
fixed_bytes!(ServiceEventId, 16, "service event ID");
fixed_bytes!(DeviceId, 16, "device ID");
fixed_bytes!(BootId, 16, "boot ID");
fixed_bytes!(PolicyId, 16, "policy ID");
fixed_bytes!(Nonce, 32, "approval nonce");
