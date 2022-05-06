// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
	hotp::Hotp,
	{error::OtpError, otp::Otp},
};
use alloc::boxed::Box;
use digest::{core_api::BlockSizeUser, Digest, FixedOutputReset, KeyInit};
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

/// A Time-based One-Time Password (TOTP) generator.
///
/// It is a one-time password generator that is based on the current time,
/// and as such, it takes a callback function that is called to get the current
/// time, allowing it to work on both modern platforms and minimalist embedded
/// platforms, as long as there is some way to get the current time.
pub struct Totp<D: Digest + BlockSizeUser + FixedOutputReset> {
	hotp: Hotp<D>,
	interval: u64,
	time_callback: Box<dyn Fn() -> u64>,
}

impl<D: Digest + BlockSizeUser + FixedOutputReset> Totp<D> {
	/// Creates a new HOTP instance, using the given bytes as the secret,
	/// the given length, and the given time callback.
	pub fn new<
		A: AsRef<[u8]>,
		L: Into<Option<usize>>,
		I: Into<Option<u64>>,
		C: Fn() -> u64 + 'static,
	>(
		key: A,
		length: L,
		interval: I,
		time_callback: C,
	) -> Result<Self, OtpError> {
		let interval = interval.into().unwrap_or(30);
		Hotp::new(key, length).map(|hotp| Totp {
			hotp,
			interval,
			time_callback: Box::new(time_callback),
		})
	}

	#[cfg(feature = "std")]
	/// Creates a new TOTP instance, using the given bytes as the secret,
	/// the given length, and the [SystemTime](std::time::SystemTime) to determine the current time.
	pub fn new_from_system_time<A: AsRef<[u8]>, L: Into<Option<usize>>, I: Into<Option<u64>>>(
		key: A,
		length: L,
		interval: I,
	) -> Result<Self, OtpError> {
		Self::new(key, length, interval, time_callback)
	}

	fn counter(&self) -> u64 {
		(*self.time_callback)() / self.interval
	}

	/// Calculate the OTP value for the given time, represented as seconds from the unix epoch.
	pub fn code_at_time(&mut self, time: u64) -> Result<Otp, OtpError> {
		self.hotp.set_counter(time);
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
}

#[cfg(feature = "std")]
fn time_callback() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("time went backwards")
		.as_secs()
}
