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

    /// Auxiliary function defined in 10.3.1
    fn hash_df<H: Digest>(seed_material: &[&[u8]], byte_count: u32) -> Result<&[u8], LengthError> {
        todo!()
        // Compute the length, this needs to know the output size of
        // the hash function which im sure is available
        hash_output_len: u32 = 32; // This is wrong!

        // len = ceil(byte_count / hash_output_len)
        len: u32 = (byte_count + hash_output_len - 1) / hash_output_len;
        if len > 255 {
            return Err; // len <= 255
        }

        // tmp should be null to begin with but will be extended...
        // not sure the nicest as to do this in no_std
        // The idea is we will generate len * hash_output_len bytes
        // and we know this now, so I guess we can preallocate?
        tmp: &[u8] = &[];

        // For the hash below we want to feed 8*byte_count as a slice of u8
        byte_count_array: [u8; 4] = (byte_count * 8).to_le_bytes()

        // Set an 8-bit counter to one to len
        for for counter in 1..=len {
            // We now want to append hash_output_len to tmp

            // Here we compute the hash over counter as a u8, the number of output bits
            // as a u32 and then the seed material passed into the function
            // hash_output = Hash(counter || (byte_count * 8) as u32 || _seed_material)
            let mut hasher = H::new();
            hasher.update(&[counter]); // counter as a u8 byte
            hasher.update(&byte_count_array); // number of bits as a 4 byte slice
            for block in seed_material {
                hasher.update(block)
            }
            hasher.finalize();

            // finally we append this hash output into tmp
            // tmp = tmp || hash_output
        }

        // The output of Hash_df is the leftmost bytes of tmp
        return OK(&tmp[..byte_count]);
    }
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
