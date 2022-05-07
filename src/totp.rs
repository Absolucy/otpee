// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
	hotp::Hotp,
	{error::OtpError, otp::Otp},
};
use alloc::boxed::Box;
use digest::{core_api::BlockSizeUser, Digest, FixedOutputReset};
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

/// A Time-based One-Time Password (TOTP) generator.
///
/// It is a one-time password generator that is based on the current time,
/// and as such, it takes a callback function that is called to get the current
/// time, allowing it to work on both modern platforms and minimalist embedded
/// platforms, as long as there is some way to get the current time.
///
/// TOTP also allows for a "skew" value, which will allow the previous N
/// or next N codes to be accepted, to account for possible time desynchronization
/// between the client and server.
///
/// ```rust
/// use otpee::Totp;
/// use sha1::Sha1;
///
/// // Initialize a new HOTP instance
/// let mut totp_sha1 = Totp::<Sha1>::new_from_system_time(b"12345678901234567890", 6, 1, 30).unwrap();
/// // Calculate the OTP value for a counter of "0"
/// let otp = totp_sha1.code().unwrap();
/// println!("The code for the current time is: {}", otp);
/// ```
pub struct Totp<D: Digest + BlockSizeUser + FixedOutputReset> {
	hotp: Hotp<D>,
	interval: u64,
	skew: usize,
	time_callback: Box<dyn Fn() -> u64>,
}

impl<D: Digest + BlockSizeUser + FixedOutputReset> Totp<D> {
	/// Creates a new HOTP instance, using the given bytes as the secret,
	/// the given length, the given skew value, and the given time callback.
	pub fn new<
		A: AsRef<[u8]>,
		L: Into<Option<usize>>,
		I: Into<Option<u64>>,
		S: Into<Option<usize>>,
		C: Fn() -> u64 + 'static,
	>(
		key: A,
		length: L,
		interval: I,
		skew: S,
		time_callback: C,
	) -> Result<Self, OtpError> {
		let interval = interval.into().unwrap_or(30);
		let skew = skew.into().unwrap_or(1);
		Hotp::new(key, length).map(|hotp| Totp {
			hotp,
			interval,
			skew,
			time_callback: Box::new(time_callback),
		})
	}

	#[cfg(feature = "std")]
	/// Creates a new TOTP instance, using the given bytes as the secret,
	/// the given length, and the [SystemTime](std::time::SystemTime) to determine the current time.
	pub fn new_from_system_time<
		A: AsRef<[u8]>,
		L: Into<Option<usize>>,
		I: Into<Option<u64>>,
		S: Into<Option<usize>>,
	>(
		key: A,
		length: L,
		interval: I,
		skew: S,
	) -> Result<Self, OtpError> {
		Self::new(key, length, interval, skew, time_callback)
	}

	fn counter(&self) -> u64 {
		(*self.time_callback)() / self.interval
	}

	/// Calculate the OTP value for the given time, represented as seconds from the unix epoch.
	pub fn code_at_time(&mut self, time: u64) -> Result<Otp, OtpError> {
		self.hotp.set_counter(time / self.interval);
		self.hotp.code()
	}

	#[cfg(feature = "std")]
	/// Calculate the OTP value for the given [SystemTime](std::time::SystemTime).
	pub fn code_at_system_time(&mut self, system_time: SystemTime) -> Result<Otp, OtpError> {
		self.code_at_time(
			system_time
				.duration_since(UNIX_EPOCH)
				.expect("time went backwards")
				.as_secs(),
		)
	}

	/// Calculate the OTP value for the current time.
	pub fn code(&mut self) -> Result<Otp, OtpError> {
		let counter = self.counter();
		self.code_at_time(counter)
	}

	/// Validates the code as being valid for the current time.
	/// This takes the skew value into account, which also allows the previous N or next N codes to be accepted.
	pub fn validate_code(&mut self, code: u32) -> bool {
		let counter = self.counter();
		for value in
			counter.saturating_sub(self.skew as u64)..=counter.saturating_add(self.skew as u64)
		{
			self.hotp.set_counter(value);
			if self.hotp.code().map(|c| c == code).unwrap_or(false) {
				return true;
			}
		}
		false
	}
}

#[cfg(feature = "std")]
fn time_callback() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("time went backwards")
		.as_secs()
}

#[cfg(test)]
mod tests {
	use super::Totp;
	use sha1::Sha1;
	use sha2::{Sha256, Sha512};

	#[test]
	fn totp_sha1() {
		let mut totp = Totp::<Sha1>::new(b"12345678901234567890", 8, 30, 0, || 0).unwrap();
		assert_eq!(totp.code_at_time(59).unwrap(), 94287082);
		assert_eq!(totp.code_at_time(1111111109).unwrap(), 7081804);
		assert_eq!(totp.code_at_time(1111111111).unwrap(), 14050471);
		assert_eq!(totp.code_at_time(1234567890).unwrap(), 89005924);
		assert_eq!(totp.code_at_time(2000000000).unwrap(), 69279037);
		assert_eq!(totp.code_at_time(20000000000).unwrap(), 65353130);
	}

	#[test]
	fn totp_sha256() {
		let mut totp =
			Totp::<Sha256>::new(b"12345678901234567890123456789012", 8, 30, 0, || 0).unwrap();
		assert_eq!(totp.code_at_time(59).unwrap(), 46119246);
		assert_eq!(totp.code_at_time(1111111109).unwrap(), 68084774);
		assert_eq!(totp.code_at_time(1111111111).unwrap(), 67062674);
		assert_eq!(totp.code_at_time(1234567890).unwrap(), 91819424);
		assert_eq!(totp.code_at_time(2000000000).unwrap(), 90698825);
		assert_eq!(totp.code_at_time(20000000000).unwrap(), 77737706);
	}

	#[test]
	fn totp_sha512() {
		let mut totp = Totp::<Sha512>::new(
			b"1234567890123456789012345678901234567890123456789012345678901234",
			8,
			30,
			0,
			|| 0,
		)
		.unwrap();
		assert_eq!(totp.code_at_time(59).unwrap(), 90693936);
		assert_eq!(totp.code_at_time(1111111109).unwrap(), 25091201);
		assert_eq!(totp.code_at_time(1111111111).unwrap(), 99943326);
		assert_eq!(totp.code_at_time(1234567890).unwrap(), 93441116);
		assert_eq!(totp.code_at_time(2000000000).unwrap(), 38618901);
		assert_eq!(totp.code_at_time(20000000000).unwrap(), 47863826);
	}
}
