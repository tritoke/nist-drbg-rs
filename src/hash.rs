use core::marker::PhantomData;

use digest::{Digest, OutputSizeUser};

use crate::arithmetic::{add_into, increment};
use crate::{Drbg, SeedError};

/// What is the maximum number of calls to Hash_DRBG before the DRBG must be reseeded?
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) table 2
pub const MAX_RESEED_INTERVAL: u64 = 1 << 48;

/// What is the recommended number of calls to Hash_DRBG before the DRBG must be reseeded?
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) Appendix B1
pub const NIST_RESEED_INTERVAL: u64 = 100_000;

pub struct HashDrbg<H: Digest, const SEEDLEN: usize> {
    // V - Value of `seedlen` bits
    value: [u8; SEEDLEN],

    // C - Constant of `seedlen` bits
    constant: [u8; SEEDLEN],

    // the number of requests for bits received since the last (re)seeding
    reseed_counter: u64,

    // Currently unused:
    // admin bits - not sure about these right now but the standard shows them
    _prediction_resistance_flag: bool, // is this drbg prediction resistant?

    _hasher: PhantomData<H>,
}

impl<H: Digest, const SEEDLEN: usize> HashDrbg<H, SEEDLEN> {
    pub fn new(
        entropy: &[u8],
        nonce: &[u8], // Jack: the nonce can be up to 128 bits (half security bits)
        // Sam: should we not check for this and raise an error?
        // Jack: I don't know if it has a max size? Any longer is a waste, but not error worthy
        personalization_string: &[u8], // this can have length zero, do we want empty slice or Option?
                                       // Sam: IMO its simple enough to just give an empty byte
                                       // slice, i.e. b"" or &[], also ideally this field should be
                                       // encouraged 😂
    ) -> Result<Self, SeedError> {
        let mut value = [0u8; SEEDLEN];
        hash_df::<H>(&[entropy, nonce, personalization_string], &mut value)?;

        let mut constant = [0u8; SEEDLEN];
        hash_df::<H>(&[&[0x00], &value], &mut constant)?;

        Ok(Self {
            value,
            constant,
            reseed_counter: 1,
            _prediction_resistance_flag: false,
            _hasher: PhantomData,
        })
    }

    fn reseed_core(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        // We hash 0x01 || V || entropy || additional_input
        let mut seed = self.value;
        hash_df::<H>(
            &[
                &[0x01],
                &self.value,
                entropy,
                additional_input.unwrap_or(b""),
            ],
            &mut seed,
        )?;
        self.value = seed;

        // We hash 0x00 || V
        hash_df::<H>(&[&[0x00], &self.value], &mut self.constant)?;
        self.reseed_counter = 1;

        Ok(())
    }

    fn random_bytes_core(
        &mut self,
        buf: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        if self.reseed_counter > NIST_RESEED_INTERVAL {
            return Err(SeedError::CounterExhausted);
        }

        if let Some(additional_input) = additional_input {
            if !additional_input.is_empty() {
                // w = Hash(0x02 || V || additional_input)
                let w = H::new_with_prefix([0x02])
                    .chain_update(self.value)
                    .chain_update(additional_input)
                    .finalize();

                // V = V + w mod 2^seedlen
                add_into(&mut self.value, &w);
            }
        }

        // Fill the buffer with bytes using hashgen and update V
        hashgen::<H, SEEDLEN>(self.value, buf);

        // Modify the V value
        // H = Hash(0x03 || V)
        let h = H::new_with_prefix([0x03])
            .chain_update(self.value)
            .finalize();

        // V = V + H + C + reseed_counter mod 2^seedlen
        add_into(&mut self.value, &h);
        add_into(&mut self.value, &self.constant);
        add_into(&mut self.value, &self.reseed_counter.to_be_bytes());

        self.reseed_counter += 1;

        Ok(())
    }
}

impl<H: Digest, const SEEDLEN: usize> Drbg for HashDrbg<H, SEEDLEN> {
    #[inline]
    fn reseed(&mut self, entropy: &[u8]) -> Result<(), SeedError> {
        self.reseed_core(entropy, None)
    }

    #[inline]
    fn reseed_extra(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), SeedError> {
        self.reseed_core(entropy, Some(additional_input))
    }

    #[inline]
    fn random_bytes(&mut self, buf: &mut [u8]) -> Result<(), SeedError> {
        self.random_bytes_core(buf, None)
    }

    #[inline]
    fn random_bytes_extra(
        &mut self,
        buf: &mut [u8],
        additional_input: &[u8],
    ) -> Result<(), crate::SeedError> {
        self.random_bytes_core(buf, Some(additional_input))
    }
}

/// Auxiliary function defined in 10.3.1
fn hash_df<H: Digest>(seed_material: &[&[u8]], out: &mut [u8]) -> Result<(), SeedError> {
    let hashsz = <H as OutputSizeUser>::output_size();
    let outsz = out.len();

    if outsz > hashsz * 255 {
        return Err(SeedError::LengthError {
            max_size: 255 * hashsz,
            requested_size: outsz,
        });
    }

    // Number of hash blocks to request
    let m = outsz.div_ceil(hashsz) as u8;
    let num_bits_to_return = (u8::BITS * outsz as u32).to_be_bytes();

    for counter in 1..=m {
        // hash_output = Hash(counter || (output_size_bytes * 8) || *seed_material)
        let mut hasher = H::new_with_prefix([counter]);
        hasher.update(num_bits_to_return);
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
        }
    }

    Ok(())
}

/// Auxiliary function defined in 10.1.1.4
fn hashgen<H: Digest, const SEEDLEN: usize>(value: [u8; SEEDLEN], out: &mut [u8]) {
    let hashsz = <H as OutputSizeUser>::output_size();
    let outsz = out.len();
    let m = outsz.div_ceil(hashsz);
    let mut data = value;
    for i in 0..m {
        // w = Hash(data)
        let w = H::new_with_prefix(data).finalize();

        // data = (data + 1) % 2^seedlen
        increment(&mut data);

        // W = W || w
        let lower = i * hashsz;
        let upper = (i + 1) * hashsz;
        if upper < out.len() {
            out[lower..upper].copy_from_slice(&w);
        } else {
            out[lower..].copy_from_slice(&w[..outsz - lower]);
        }
    }
}

#[cfg(feature = "sha1")]
pub type Sha1Drbg = HashDrbg<sha1::Sha1, { 440 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha224Drbg = super::HashDrbg<sha2::Sha224, { 440 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha512_224Drbg = super::HashDrbg<sha2::Sha512_224, { 440 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha256Drbg = super::HashDrbg<sha2::Sha256, { 440 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha512_256Drbg = super::HashDrbg<sha2::Sha512_256, { 440 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha384Drbg = super::HashDrbg<sha2::Sha384, { 888 / 8 }>;

#[cfg(feature = "sha2")]
pub type Sha512Drbg = super::HashDrbg<sha2::Sha512, { 888 / 8 }>;
