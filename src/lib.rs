#![no_std]

use core::{error::Error, fmt::Display};

// Should we feature lock this? We don't need it for Hmac, but will for Hash
// and CTR
pub mod arithmetic;

#[cfg(any(feature = "sha1", feature = "sha2"))]
pub mod hash;

#[cfg(any(feature = "sha1", feature = "sha2"))]
pub use hash::*;

#[cfg(any(feature = "hmac-sha1", feature = "hmac-sha2"))]
pub mod hmac;

#[cfg(any(feature = "hmac-sha1", feature = "hmac-sha2"))]
pub use hmac::*;

#[cfg(feature = "aes-ctr")]
pub mod ctr;

#[cfg(feature = "aes-ctr")]
pub use ctr::*;

#[derive(Debug)]
pub enum SeedError {
    InsufficientEntropy,
    LengthError {
        max_size: usize,
        requested_size: usize,
    },
    EmptyNonce,
    CounterExhausted,
}

impl Display for SeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SeedError::InsufficientEntropy => f.write_str("Insufficient entropy was provided to meet the minimum supported entropy level of 112 bits"),
            SeedError::LengthError { max_size, requested_size } => {
                write!(f, "Requested size of {requested_size} bytes exceeds maximum size of {max_size} bytes")
            },
            SeedError::EmptyNonce => f.write_str("Nonce must not be empty"),
            SeedError::CounterExhausted => f.write_str("Counter has been exhaused, reseed")
        }
    }
}

impl Error for SeedError {}

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
pub trait Drbg {
    fn reseed(&mut self, entropy: &[u8]) -> Result<(), SeedError>;
    fn reseed_extra(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), SeedError>;

    fn random_bytes(&mut self, buf: &mut [u8]) -> Result<(), SeedError>;
    fn random_bytes_extra(
        &mut self,
        buf: &mut [u8],
        additional_input: &[u8],
    ) -> Result<(), SeedError>;
}
