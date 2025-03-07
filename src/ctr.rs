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
            ctr_drbg_df::<C, SEEDLEN>(&[entropy, nonce, personalization_string], &mut seed_material[..]);
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
            seed_material[..personalization_string.len()].copy_from_slice(personalization_string);

            // Finally compute
            // seed_material = entropy ^ pad(personalization_string)
            xor_into(&mut seed_material[..], &entropy);
        }

        // For instantiation, both key and value should be all zeros
        // Default key:   0x00 ... 0x00 (Key length)
        // Default value: 0x00 ... 0x00 (Block length)
        for (ki, vi) in key.iter_mut().zip(value.iter_mut()) {
            *ki = 0u8; // Set key and value elements to 0x00
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
        ctr_drbg.ctr_drbg_update(&seed_material);
        Ok(ctr_drbg)
    }

    // Auxiliary function in section 10.1.2.2
    fn ctr_drbg_update(&mut self, provided_data: &[u8]) {
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

        // TODO: I need to cast from slices back to the generic arrays, this is broken
        // set key as the left most bytes of tmp
        let key_len = self.key.len();
        self.key.copy_from_slice(&tmp[..key_len]);

        // set value as the rightmost bytes of tmp
        self.value.copy_from_slice(&tmp[key_len..]);

    }

    fn reseed_core(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        // Whether or not we use a derivation_function, we first populate
        // seed_material with the user input
        let mut seed_material: [u8; SEEDLEN] = [0; SEEDLEN];

        // If additional_input is None, use &[] for now...
        let additional_input = match additional_input {
            Some(v) => v,
            None => &[],
        };

        // When a derivation function is used then the entropy input is
        // seed_material = entropy || additional_input
        // which must have length SEEDLEN
        if self.derivation_function {
            // Ensure that entropy || nonce || personalization_string
            // as exactly length BlockSize + KeySize
            if entropy.len() + additional_input.len() != SEEDLEN {
                return Err(SeedError::LengthError {
                    max_size: SEEDLEN, // TODO this is really a precise, rather than max issue, different error?
                    requested_size: entropy.len() + additional_input.len(),
                });
            }
            // Compute the seed material from the derivation function and user supplied entropy
            ctr_drbg_df::<C, SEEDLEN>(&[entropy, additional_input], &mut seed_material[..]);
        }
        // Otherwise seed_material = entropy ^ pad(personalization_string)
        else {
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
            seed_material.copy_from_slice(additional_input);

            // Compute:
            // seed_material = entropy ^ pad(additional_data)
            xor_into(&mut seed_material[..], &entropy);
        }

        // Set key, V using the update function
        self.ctr_drbg_update(&seed_material);
        self.reseed_counter = 1;

        Ok(())
    }

    fn random_bytes_core(
        &mut self,
        buf: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        // TODO: check reseed counter
        if self.reseed_counter > 99999 {
            return Err(SeedError::CounterExhausted);
        }

        // pad additional input to length SEEDLEN
        let mut seed_material: [u8; SEEDLEN] = [0; SEEDLEN];
        match additional_input {
            Some(v) => {
                seed_material[..v.len()].copy_from_slice(v);
                self.ctr_drbg_update(&seed_material);
            },
            None => ()
        };

        // Create a cipher to encrypt blocks
        let cipher = C::new(&self.key);

        // Fill buf with random bytes by repeatedly appending encryptions
        let block_len = C::block_size();
        let bufsz = buf.len();
        let m = bufsz.div_ceil(block_len);
        for i in 0..m {
            // If ctr_len < blocklen
            // TODO what is ctr_len? The table just says 4 <= ctr_ln <= block_len
            // Else
            // V = V + 1 mod 2^block_len
            increment(&mut self.value);

            // Add an encryption block, note encrypt_block works in-place
            let mut ct = self.value.clone(); // TODO do i have to clone?
            cipher.encrypt_block(&mut ct);

            // buf = buf || Enc_K(V)
            let lower = i * block_len;
            let upper = (i + 1) * block_len;
            if upper < bufsz {
                buf[lower..upper].copy_from_slice(&ct);
            } else {
                buf[lower..].copy_from_slice(&ct[..bufsz - lower]);
            }
        }

        // Update for backtracking resistance
        self.ctr_drbg_update(&seed_material);
        self.reseed_counter += 1;

        Ok(())
    }
}

/// Aux function in 10.3.2
/// we really want to return this: [u8; C:BlockSize + C:KeySize] or should
/// we include this into the input like with hash_df
fn ctr_drbg_df<C: BlockCipher + KeyInit + BlockEncrypt, const SEEDLEN: usize>(seed_material: &[&[u8]], out: &mut [u8]) {
    // TODO: max len of out should be 512 bits

    // Compute the length of the input and output as four bytes big endian
    let input_len: usize = seed_material.iter().map(|block| block.len()).sum();
    let input_len_bytes = (input_len as u32).to_be_bytes();
    let output_len_bytes = (out.len() as u32).to_be_bytes();

    // Now we need the value S = L || N || input || 0x80 || 0x00 ... 0x00
    // where we only pad with zeros to ensure S has length SEEDLEN
    if (4 + 4 + input_len + 1) > SEEDLEN {
        todo!()
    }
    // s should be left padded with zeros to match the out-length which is always the seed length
    let mut s :[u8; SEEDLEN] = [0; SEEDLEN];
    s[..4].copy_from_slice(&input_len_bytes);
    s[4..8].copy_from_slice(&output_len_bytes);

    // Fill s with all slices within seed_material
    // This seems like a not-very-rust way to solve this!
    let mut byte_counter = 0;
    for block in seed_material {
        s[8 + byte_counter.. 8 + byte_counter + block.len()].copy_from_slice(&block);
        byte_counter += block.len();
    }
    assert!(byte_counter == input_len);

    // Add a 0x80 byte to pad
    s[8 + byte_counter] = 0x80;

    // Create the key 0x00 0x01 0x02 ... 0xXX
    let mut key = GenericArray::<u8, C::KeySize>::default();
    for (i, ki) in key.iter_mut().enumerate() {
        *ki = i as u8;
    }

    todo!()
}

/// Helper function which computes A = A XOR B
fn xor_into(a: &mut [u8], b: &[u8]) {
    // Ensure len(b) <= len(a)
    if b.len() > a.len() {
        panic!("b_blocks is too short to XOR with a"); // TODO: proper error handling
    }
    for (ai, bi) in a.iter_mut().zip(b.iter()) {
        *ai ^= bi
    }
}

fn bcc() {
    todo!()
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
