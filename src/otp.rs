// SPDX-License-Identifier: MIT OR Apache-2.0
use alloc::fmt::{self, Display, Formatter};
use constant_time_eq::constant_time_eq;
use core::{cmp::PartialEq, convert::AsRef, ops::Deref};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// A one-time password.
/// Can just be treated like a normal number, while also having a
/// [Display] implementation that shows it padded with zeroes.
pub struct Otp {
	code: u32,
	length: usize,
}

impl Otp {
	#[inline]
	pub(crate) fn new(code: u32, length: usize) -> Self {
		Self { code, length }
	}
}

impl Deref for Otp {
	type Target = u32;

	#[inline]
	fn deref(&self) -> &Self::Target {
		&self.code
	}
}

impl AsRef<u32> for Otp {
	#[inline]
	fn as_ref(&self) -> &u32 {
		&self.code
	}
}

impl PartialEq<u32> for Otp {
	#[inline]
	fn eq(&self, other: &u32) -> bool {
		constant_time_eq(&self.to_ne_bytes(), &other.to_ne_bytes())
	}
}

impl Display for Otp {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		#[cfg(feature = "std")]
		return write!(f, "{:0width$}", self.code, width = self.length);

		#[cfg(not(feature = "std"))]
		{
			use alloc::{
				string::{String, ToString},
				vec::Vec,
			};

			let mut out = core::iter::repeat('0')
				.take(self.length)
				.collect::<Vec<char>>();
			let out_len = out.len();
			let code = self.code.to_string().chars().collect::<Vec<char>>();
			let code_length = code.len();
			assert!(code_length <= out_len);
			let start = out_len - code_length;
			out[start..].copy_from_slice(&code);

			return f.write_str(&out.into_iter().collect::<String>());
		}
	}
}
