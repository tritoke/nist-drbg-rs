use core::{error::Error, fmt::Display, marker::PhantomData};

use digest::{Digest, OutputSizeUser};

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
    // Jack: NIST doc says security_strength is optional for Hash_DRBG as it is unused.
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
        _nonce: &[u8], // Jack: the nonce can be up to 128 bits (half security bits)
        _personalisation_string: &[u8], // this can have length zero, do we want empty slice or Option?
    ) -> Result<Self, InsufficientEntropyError> {
        todo!()

        // Rough idea based on my reading of the spec
        // NOTE: not sure the nicest was to concat slices in no_std
        // seed_material = entropy || nonce || personalisation_string
        // self.value = hash_df(seed_material, SEEDLEN_BYTES)
        // self.constant = hash_df(0x00 | V, SEEDLEN_BYTES)
        // self.reseed_counter = 1
    }
}

#[derive(Debug)]
pub struct LengthError {
    max_size: usize,
    requested_size: usize,
}

impl Display for LengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Requested size of {} bytes exceeds maximum size of {} bytes",
            self.requested_size, self.max_size,
        )
    }
}

impl Error for LengthError {}

/// Auxiliary function defined in 10.3.1
fn hash_df<H: Digest>(seed_material: &[&[u8]], out: &mut [u8]) -> Result<(), LengthError> {
    let hashsz = <H as OutputSizeUser>::output_size();
    let outsz = out.len();

    if outsz > hashsz * 255 {
        return Err(LengthError {
            max_size: 255 * hashsz,
            requested_size: outsz,
        });
    }

    // Set an 8-bit counter to one to len
    for counter in 1..=255 {
        // hash_output = Hash(counter || (output_size_bytes * 8) || *seed_material)
        let mut hasher = H::new_with_prefix([counter]);
        hasher.update((u8::BITS * outsz as u32).to_le_bytes());
        for block in seed_material {
            hasher.update(block)
        }
        let hash_output = hasher.finalize();

        // counter starts from 1 so offset to get the index
        let lower = (counter as usize - 1) * hashsz;
        let upper = counter as usize * hashsz;
        if upper < out.len() {
            out[lower..upper].copy_from_slice(&hash_output);
        } else {
            out[lower..].copy_from_slice(&hash_output[..outsz - lower]);
            break;
        }
    }

    Ok(())
}

impl<H: Digest, const SEEDLEN: usize, const HSSS: u32> Drbg for HashDrbg<H, SEEDLEN, HSSS> {
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
