use aes::cipher::BlockEncrypt;
use aes::cipher::{BlockCipher, KeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes192, Aes256};

use crate::arithmetic::increment;
use crate::{Drbg, SeedError};

pub struct CtrDrbg<C: BlockCipher + KeyInit + BlockEncrypt, const SEEDLEN: usize> {
    // key - Value of `seedlen` bits
    key: GenericArray<u8, C::KeySize>,

    // V - Value of `seedlen` bits
    value: GenericArray<u8, C::BlockSize>,

    // the number of requests for bits received since the last (re)seeding
    reseed_counter: u64,

    // Whether or not to use a derivation function for seeding and reseeding
    derivation_function: bool,

    // Currently unused:
    // admin bits - not sure about these right now but the standard shows them
    _prediction_resistance_flag: bool, // is this drbg prediction resistant?
}

impl<C: BlockCipher + KeyInit + BlockEncrypt, const SEEDLEN: usize> CtrDrbg<C, SEEDLEN> {
    pub fn new(
        entropy: &[u8],
        nonce: &[u8],
        personalization_string: &[u8],
        derivation_function: bool,
    ) -> Result<Self, SeedError> {
        let mut key = GenericArray::<u8, C::KeySize>::default();
        let mut value = GenericArray::<u8, C::BlockSize>::default();
        let mut seed_material: [u8; SEEDLEN] = [0; SEEDLEN];

        // Ensure the personalization string is not too long
        if personalization_string.len() > SEEDLEN {
            return Err(SeedError::LengthError {
                max_size: SEEDLEN, // TODO this is really a precise, rather than max issue, different error?
                requested_size: personalization_string.len(),
            });
        }

        // When a derivation function is used then the entropy input is
        // seed_material = entropy || nonce || personalization_string
        // which is fed into a derivation function before being used
        // as the value to be processed by ctr_drbg_update
        if derivation_function {
            // Ensure that entropy || nonce || personalization_string
            // as exactly length BlockSize + KeySize
            if entropy.len() + nonce.len() + personalization_string.len() != SEEDLEN {
                return Err(SeedError::LengthError {
                    max_size: SEEDLEN, // TODO this is really a precise, rather than max issue, different error?
                    requested_size: entropy.len() + nonce.len() + personalization_string.len(),
                });
            }
            // Compute the seed material from the derivation function and user supplied entropy
            ctr_df::<C, SEEDLEN>(&[entropy, nonce, personalization_string], &mut seed_material[..]);
        }
        // Otherwise seed_material = entropy ^ pad(personalization_string)
        else {
            if !nonce.is_empty() {
                return Err(SeedError::CounterExhausted); // TODO this should be a new error, lazy
            }
            // Ensure that entropy has length SEEDLEN
            if entropy.len() != SEEDLEN {
                return Err(SeedError::LengthError {
                    max_size: SEEDLEN, // TODO this is really a precise, rather than max issue, different error?
                    requested_size: entropy.len(),
                });
            }

            // The personalization string must be padded with zeros on the right to
            // ensure it has length SEEDLEN. We can do this by copying personalization_string
            // into seed_material
            seed_material.copy_from_slice(personalization_string);

            // Finally compute
            // seed_material = entropy ^ personalization_string
            xor_into(&mut seed_material[..], &[entropy]);
        }

        // For instantiation, both key and value should be all zeros
        // Default key:   0x00 ... 0x00 (Key length)
        // Default value: 0x00 ... 0x00 (Block length)
        for (ki, vi) in key.iter_mut().zip(value.iter_mut()) {
            *ki = 0; // Set key and value elements to 0x00
            *vi = 0;
        }

        // We now have default values and processed seed material, which
        // we now pass into the update function
        let mut ctr_drbg = Self {
            key,
            value,
            reseed_counter: 1,
            derivation_function,
            _prediction_resistance_flag: false,
        };
        ctr_drbg.ctr_drbg_update(&[entropy, nonce, personalization_string]);
        Ok(ctr_drbg)
    }

    // Auxiliary function in section 10.1.2.2
    fn ctr_drbg_update(&mut self, provided_data: &[&[u8]]) {
        // Buffer to fill with update bytes
        let mut tmp: [u8; SEEDLEN] = [0; SEEDLEN];

        // Create a cipher to encrypt blocks
        let cipher = C::new(&self.key);
        
        let block_len = C::block_size();
        let m = SEEDLEN.div_ceil(block_len);
        for i in 0..m {
            // If ctr_len < blocklen
            // TODO what is ctr_len? The table just says 4 <= ctr_ln <= block_len
            // Else
            // V = V + 1 mod 2^block_len
            increment(&mut self.value);

            // Add an encryption block, note encrypt_block works in-place
            let mut ct = self.value.clone(); // TODO do i have to clone?
            cipher.encrypt_block(&mut ct);
            
            // tmp = tmp || Enc_K(V)
            let lower = i * block_len;
            let upper = (i + 1) * block_len;
            if upper < SEEDLEN {
                tmp[lower..upper].copy_from_slice(&ct);
            } else {
                tmp[lower..].copy_from_slice(&ct[..SEEDLEN - lower]);
            }
        }

        // tmp = tmp XOR provided_data
        xor_into(&mut tmp, provided_data);

        // set key as the left most bytes of tmp
        self.key = tmp[..self.key.len()].try_into().unwrap();

        // set value as the rightmost bytes of tmp
        self.value = tmp[self.key.len()..].try_into().unwrap();

    }

    fn reseed_core(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        todo!()
    }

    fn random_bytes_core(
        &mut self,
        buf: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        todo!()
    }
}

/// Aux function in 10.3.2
/// we really want to return this: [u8; C:BlockSize + C:KeySize] or should
/// we include this into the input like with hash_df
fn ctr_df<C: BlockCipher + KeyInit + BlockEncrypt, const SEEDLEN: usize>(seed_material: &[&[u8]], out: &mut [u8]) {
    // TODO: max len of out should be 512 bits

    // Compute the length of the input and output as four bytes big endian
    let input_len: usize = seed_material.iter().map(|block| block.len()).sum();
    let input_len_bytes = (input_len as u32).to_be_bytes();
    let output_len_bytes = (out.len() as u32).to_be_bytes();

    // Now we need the value S = L || N || input || 0x80 || 0x00 ... 0x00
    // where we only pad with zeros to ensure S has length SEEDLEN
    if (4 + 4 + input_len + 1) > SEEDLEN {
        // This should be an error, i think? Unless we know this is never true
        todo!()
    }
    todo!();
}

/// Helper function which computes A = A XOR B
fn xor_into(a: &mut [u8], b_blocks: &[&[u8]]) {
    // Calculate the total length of b_blocks
    let total_length: usize = b_blocks.iter().map(|block| block.len()).sum();
    if total_length < a.len() {
        panic!("b_blocks is too short to XOR with a"); // TODO: proper error handling
    }
    for (ai, bi) in a.iter_mut().zip(b_blocks.iter().flat_map(|block| *block)) {
        *ai ^= bi
    }
}

impl<C: BlockCipher + KeyInit + BlockEncrypt, const SEEDLEN: usize> Drbg for CtrDrbg<C, SEEDLEN> {
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

// SEEDLEN = BlockSize + KeySize
#[cfg(feature = "aes-ctr")]
pub type AesCtr128Drbg = super::CtrDrbg<Aes128, { 16 + 16 }>;

#[cfg(feature = "aes-ctr")]
pub type AesCtr192Drbg = super::CtrDrbg<Aes192, { 24 + 16 }>;

#[cfg(feature = "aes-ctr")]
pub type AesCtr256Drbg = super::CtrDrbg<Aes256, { 32 + 16 }>;
