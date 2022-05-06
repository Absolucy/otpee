// SPDX-License-Identifier: MIT OR Apache-2.0
use alloc::fmt::{self, Display, Formatter};
#[cfg(feature = "std")]
use std::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtpError {
	InvalidLength,
	HashTooShort,
	CounterOverflow,
}

impl Display for OtpError {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			OtpError::InvalidLength => {
				f.write_str("attempted to create a HOTP instance with an invalid key length")
			}
			OtpError::HashTooShort => {
				f.write_str("the hash function used in the HOTP instance's output is too short")
			}
			OtpError::CounterOverflow => f.write_str("the HOTP instance's counter has overflowed"),
		}
	}
}

#[cfg(feature = "std")]
impl Error for OtpError {}
