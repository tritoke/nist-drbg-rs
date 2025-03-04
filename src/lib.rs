#![no_std]

use core::marker::Sized;

#[cfg(any(feature = "sha1", feature = "sha2"))]
pub mod hash;

#[cfg(any(feature = "sha1", feature = "sha2"))]
pub use hash::*;

pub enum SeedError {
    InsufficientEntropy,
}

// NOTES:
// seed (called instantiate in the NIST spec)
// nonce is needed for HMAC and HASH but not CTR, maybe we don't include this for Drbg?
// personalization_string is basically optional context bytes to add into seeding
// security strength is an int which is optional and defaults to 32 when missing I believe
//
// reseed
// like personalization_string above, additional_input are optional context bytes you can
// feed into the reseed
//
// random_bytes (generate in the NIST spec)
// NOTE: in the NIST api you request a number of BITS, but this API fills a buffer of bytes
// again, additional_input are optional bytes to feeding into the generate function
pub trait Drbg: Sized {
    fn reseed(&mut self, entropy: &[u8], additional_input: Option<&[u8]>) -> Result<(), SeedError>;
    fn random_bytes(&mut self, buf: &mut [u8], additional_input: Option<&[u8]>);
}
