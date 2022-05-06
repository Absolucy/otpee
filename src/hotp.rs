// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{error::OtpError, otp::Otp};
use digest::{core_api::BlockSizeUser, Digest, FixedOutputReset, KeyInit};
use hmac::{Mac, SimpleHmac};

#[derive(Debug, Clone)]
pub struct Hotp<D: Digest + BlockSizeUser + FixedOutputReset> {
	hasher: SimpleHmac<D>,
	counter: u64,
	length: usize,
}

impl<D: Digest + BlockSizeUser + FixedOutputReset> Hotp<D> {
	/// Creates a new HOTP instance, using the given bytes as the secret.
	pub fn new<A: AsRef<[u8]>, L: Into<Option<usize>>>(
		key: A,
		length: L,
	) -> Result<Self, OtpError> {
		let length = length.into().unwrap_or(6);
		<SimpleHmac<D> as KeyInit>::new_from_slice(key.as_ref())
			.map(|hasher| Hotp {
				hasher,
				counter: 0,
				length,
			})
			.map_err(|_| OtpError::InvalidLength)
	}

	/// Creates a new HOTP instance, using a hasher given by the caller.
	pub fn with_hasher<L: Into<Option<usize>>>(hasher: SimpleHmac<D>, length: L) -> Self {
		let length = length.into().unwrap_or(6);
		Hotp {
			hasher,
			counter: 0,
			length,
		}
	}

	/// Returns the current counter value.
	#[inline]
	pub fn counter(&self) -> u64 {
		self.counter
	}

	/// Increments the counter value.
	pub fn increment_counter(&mut self) -> Result<u64, OtpError> {
		self.counter = self
			.counter
			.checked_add(1)
			.ok_or(OtpError::CounterOverflow)?;
		Ok(self.counter)
	}

	/// Sets the counter to the specified value.
	#[inline]
	pub fn set_counter(&mut self, counter: u64) {
		self.counter = counter;
	}

	/// Calculate the OTP value, using the current counter.
	/// This does NOT increment the counter!
	pub fn code(&mut self) -> Result<Otp, OtpError> {
		// Calculate the hash of the current counter, in big-endian format
		let counter = self.counter.to_be_bytes();
		self.hasher.update(&counter);
		let digest = self.hasher.finalize_fixed_reset();
		let digest_len = digest.len();
		// Now, we need to get the length of the hash, minus 4.
		let usable_digest_len = digest_len.checked_sub(4).ok_or(OtpError::HashTooShort)?;
		// The offset is calculated from moduloing the last byte of the hash with that.
		let offset = *digest.last().ok_or(OtpError::HashTooShort)? as usize % usable_digest_len;
		// Now, to get our 4 bytes and turn it into a u32;
		let mut code = [0u8; 4];
		code.copy_from_slice(&digest[offset..offset + 4]);
		let code_base = u32::from_be_bytes(code);
		// And here we go calculating the OTP value.
		const TWO_THIRTY_ONE: u32 = 2_u32.pow(31);
		let code = (code_base % TWO_THIRTY_ONE) % 10_u32.pow(self.length as u32);
		Ok(Otp::new(code, self.length))
	}

	/// Calculates the OTP value using the current counter,
	/// and then increments the counter afterwards.
	pub fn code_increment(&mut self) -> Result<Otp, OtpError> {
		let code = self.code()?;
		self.increment_counter()?;
		Ok(code)
	}
}

#[cfg(test)]
mod tests {
	use super::Hotp;
	use sha1::Sha1;

	#[test]
	fn hmac_sha1_tests() {
		let mut hotp = Hotp::<Sha1>::new(b"12345678901234567890", 6).unwrap();
		assert_eq!(hotp.code_increment().unwrap(), 755224);
		assert_eq!(hotp.code_increment().unwrap(), 287082);
		assert_eq!(hotp.code_increment().unwrap(), 359152);
		assert_eq!(hotp.code_increment().unwrap(), 969429);
		assert_eq!(hotp.code_increment().unwrap(), 338314);
		assert_eq!(hotp.code_increment().unwrap(), 254676);
		assert_eq!(hotp.code_increment().unwrap(), 287922);
		assert_eq!(hotp.code_increment().unwrap(), 162583);
		assert_eq!(hotp.code_increment().unwrap(), 399871);
		assert_eq!(hotp.code_increment().unwrap(), 520489);
	}
}
