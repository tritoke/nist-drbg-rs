use core::{error::Error, fmt::Display, marker::PhantomData};

use digest::Digest;

use crate::Drbg;

// HSSS is the highest supported security strength in bits
#[allow(dead_code)]
pub struct HashDrbg<H: Digest, const SEEDLEN_BYTES: usize, const HSSS: u32> {
    // V - Value of `seedlen` bits
    value: [u8; SEEDLEN_BYTES],

    // C - Constant of `seedlen` bits
    constant: [u8; SEEDLEN_BYTES],

    // the number of requests for bits received since the last (re)seeding
    reseed_counter: u64,

    // admin bits - not sure about these right now but the standard shows them
    security_strength: u32,           // ?? ig
    prediction_resistance_flag: bool, // is this drbg prediction resistant?

    _hasher: PhantomData<H>,
}

#[derive(Debug)]
pub struct InsufficientEntropyError;

impl Display for InsufficientEntropyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Insufficient entropy was provided to meet the minimum supported entropy level of 112 bits")
    }
}

impl Error for InsufficientEntropyError {}

impl<H: Digest, const SEEDLEN: usize, const HSSS: u32> HashDrbg<H, SEEDLEN, HSSS> {
    pub fn new(
        _entropy: &[u8],
        _nonce: u64,
        _personalisation_string: &[u8],
    ) -> Result<Self, InsufficientEntropyError> {
        todo!()
    }
}

impl<H: Digest, const SEEDLEN: usize, const HSSS: u32> Drbg for HashDrbg<H, SEEDLEN, HSSS> {
    fn seed(
        _entropy: &[u8],
        _nonce: Option<&[u8]>,
        _personalization_string: Option<&[u8]>,
        _security_strength: Option<u8>,
    ) -> Result<Self, crate::SeedError> {
        todo!()
    }

    fn reseed(
        &mut self,
        _entropy: &[u8],
        _additional_input: Option<&[u8]>,
    ) -> Result<(), crate::SeedError> {
        todo!()
    }

    fn random_bytes(&mut self, _buf: &mut [u8], _additional_input: Option<&[u8]>) {
        todo!()
    }
}

// Highest support security levels from NIST 900-57: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
#[cfg(feature = "sha1")]
pub type Sha1Drbg = HashDrbg<sha1::Sha1, { 440 / 8 }, 128>;

#[cfg(feature = "sha2")]
pub type Sha224Drbg = super::HashDrbg<sha2::Sha224, { 440 / 8 }, 192>;

#[cfg(feature = "sha2")]
pub type Sha512_224Drbg = super::HashDrbg<sha2::Sha512_224, { 440 / 8 }, 192>;

#[cfg(feature = "sha2")]
pub type Sha256Drbg = super::HashDrbg<sha2::Sha256, { 440 / 8 }, 256>;

#[cfg(feature = "sha2")]
pub type Sha512_256Drbg = super::HashDrbg<sha2::Sha512_256, { 440 / 8 }, 256>;

#[cfg(feature = "sha2")]
pub type Sha384Drbg = super::HashDrbg<sha2::Sha384, { 888 / 8 }, 256>;

#[cfg(feature = "sha2")]
pub type Sha512Drbg = super::HashDrbg<sha2::Sha512, { 888 / 8 }, 256>;
