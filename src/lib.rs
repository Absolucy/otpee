// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod error;
pub mod hotp;
pub mod otp;
pub mod totp;

pub use hotp::Hotp;
pub use otp::Otp;
pub use totp::Totp;
