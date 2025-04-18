use aes::cipher::BlockEncrypt;
use aes::cipher::{BlockCipher, KeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes192, Aes256};
use des::TdesEde3;

use crate::arithmetic::increment;
use crate::{Drbg, SeedError};

pub struct CtrDrbg<C: BlockCipher + KeyInit + BlockEncrypt, const SEEDLEN: usize> {
    // key used for block cipher encryption
    key: GenericArray<u8, C::KeySize>,

    // V - value which has blocklen bits
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
    pub fn new(entropy: &[u8], personalization_string: &[u8]) -> Result<Self, SeedError> {
        // TODO: Do proper length checks here
        Self::new_impl(entropy, None, personalization_string)
    }

    pub fn new_with_df(
        entropy: &[u8],
        nonce: &[u8],
        personalization_string: &[u8],
    ) -> Result<Self, SeedError> {
        // TODO: Do proper length checks here
        Self::new_impl(entropy, Some(nonce), personalization_string)
    }

    fn new_impl(
        entropy: &[u8],
        nonce: Option<&[u8]>,
        personalization_string: &[u8],
    ) -> Result<Self, SeedError> {
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
        if let Some(nonce) = &nonce {
            // Compute the seed material from the derivation function and user supplied entropy
            ctr_drbg_df::<C, SEEDLEN>(
                &[entropy, nonce, personalization_string],
                &mut seed_material[..],
            );
        }
        // Otherwise seed_material = entropy ^ pad(personalization_string)
        else {
            // The personalization string must be padded with zeros on the right to
            // ensure it has length SEEDLEN. We can do this by copying personalization_string
            // into seed_material
            seed_material[..personalization_string.len()].copy_from_slice(personalization_string);

            // Finally compute
            // seed_material = entropy ^ pad(personalization_string)
            xor_into(&mut seed_material[..], entropy);
        }

        // We now have the processed seed material, which
        // we now pass into the update function
        let mut ctr_drbg = Self {
            // Default value is zeroed
            key: Default::default(),
            value: Default::default(),
            reseed_counter: 1,
            derivation_function: nonce.is_some(),
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
            // TODO: here we assume ctr_len = block_len
            // if we allow ctr_len within the range 4 <= ctr_ln <= block_len
            // we need to adjust the increment below.

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

        // set key as the leftmore and value as the rightmost bytes of tmp
        let key_len = self.key.len();
        self.key.copy_from_slice(&tmp[..key_len]);
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

        // If additional_input is None, use b"" for now...
        let additional_input = additional_input.unwrap_or(b"");

        // When a derivation function is used then the entropy input is
        // seed_material = entropy || additional_input
        // which must have length SEEDLEN
        if self.derivation_function {
            // TODO: can additional_input be empty for this case?
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
            seed_material[..additional_input.len()].copy_from_slice(additional_input);

            // Compute:
            // seed_material = entropy ^ pad(additional_data)
            xor_into(&mut seed_material[..], entropy);
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
        let mut seed_material: [u8; SEEDLEN] = [0; SEEDLEN];

        // Deal with the additional input, if it is not empty
        let additional_input = additional_input.unwrap_or(b"");
        if !additional_input.is_empty() {
            // When a derivation function is used, the seed material is generated
            // directly from the additional data
            if self.derivation_function {
                ctr_drbg_df::<C, SEEDLEN>(&[additional_input], &mut seed_material[..]);
            }
            // Otherwise we simply pad the additional input to the length of the seed
            else {
                seed_material[..additional_input.len()].copy_from_slice(additional_input);
            }
            self.ctr_drbg_update(&seed_material);
        }

        // Create a cipher to encrypt blocks
        let cipher = C::new(&self.key);

        // Fill buf with random bytes by repeatedly appending encryptions
        let block_len = C::block_size();
        let bufsz = buf.len();
        let m = bufsz.div_ceil(block_len);
        for i in 0..m {
            // TODO: here we assume ctr_len = block_len
            // if we allow ctr_len within the range 4 <= ctr_ln <= block_len
            // we need to adjust the increment below.

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
fn ctr_drbg_df<C: BlockCipher + KeyInit + BlockEncrypt, const SEEDLEN: usize>(
    seed_material: &[&[u8]],
    out: &mut [u8],
) {
    // TODO: max len of out should be 512 bits
    // In reality out is always length SEEDLEN
    assert!(out.len() == SEEDLEN);

    /*
     * This first block of code is to make: S = L || N || input || 0x80 || 0x00 ... 0x00
     * however, we don't know the length of the input at compile time, so instead of allocating
     * space for this at runtime, we instead modify the bcc function to take the input data and
     * then encrypt this with BCC and pad during runtime.
     */

    /*
     * This step makes a key 0x00 0x01 0x02 ... 0xXX and uses this to encrypt
     * a value with BCC to generate SEEDLEN bytes which are used to derive a
     * new key and new value X which we use to fill the output buffer
     */
    let mut key = GenericArray::<u8, C::KeySize>::default();
    for (i, ki) in key.iter_mut().enumerate() {
        *ki = i as u8;
    }

    // Fill the output bytes with values from BCC to generate SEEDLEN new bytes
    let mut iv = GenericArray::<u8, C::BlockSize>::default();
    let mut ct = GenericArray::<u8, C::BlockSize>::default();
    let block_len = C::block_size();
    let outsz = out.len();
    let m = outsz.div_ceil(block_len);
    for i in 0..m {
        // IV = (i as u32 to big endian bytes) || 0x00 ... 0x00
        iv[..4].copy_from_slice(&(i as u32).to_be_bytes());

        // now we obtain block_size bytes from BCC
        bcc::<C, SEEDLEN>(&key, &iv, seed_material, &mut ct);

        // out = out || BCC(K, IV || S)
        let lower = i * block_len;
        let upper = (i + 1) * block_len;
        if upper < outsz {
            out[lower..upper].copy_from_slice(&ct);
        } else {
            out[lower..].copy_from_slice(&ct[..outsz - lower]);
        }
    }

    // Now we set the key to the first bytes of out and X to the next block_size bytes
    let key_len = key.len();
    key.copy_from_slice(&out[..key_len]);
    ct.copy_from_slice(&out[key_len..]);

    /*
     * Now we have a new key and value X = ct, we repeatedly encrypt this and fill the out
     * buffer with these bytes
     */
    let cipher = C::new(&key);
    for i in 0..m {
        // Note that encryption works in place
        cipher.encrypt_block(&mut ct);

        // out = out || Enc(K, ct)
        let lower = i * block_len;
        let upper = (i + 1) * block_len;
        if upper < outsz {
            out[lower..upper].copy_from_slice(&ct);
        } else {
            out[lower..].copy_from_slice(&ct[..outsz - lower]);
        }
    }
}

/// Helper function which computes A = A XOR B
fn xor_into(a: &mut [u8], b: &[u8]) {
    debug_assert_eq!(
        a.len(),
        b.len(),
        "xor_into called on slices with mismatching lengths"
    );

    for (ai, bi) in a.iter_mut().zip(b.iter()) {
        *ai ^= bi
    }
}

fn bcc<C: BlockCipher + KeyInit + BlockEncrypt, const SEEDLEN: usize>(
    key: &GenericArray<u8, C::KeySize>,
    iv: &[u8],
    data: &[&[u8]],
    out: &mut GenericArray<u8, C::BlockSize>,
) {
    // Instead of taking a value S as input, in out implementation we are given
    // some data of type &[&u8], and we need to create blocks during runtime of
    // the format
    //     s = L || N || data.flatten() || 0x80 || 0x00 ... 0x00
    // right padded with zeros so that there's an exactly block length

    // Compute the length of the input and output as four bytes big endian
    let input_len: usize = data.iter().map(|block| block.len()).sum();
    let input_len_bytes = (input_len as u32).to_be_bytes();
    let output_len_bytes = (SEEDLEN as u32).to_be_bytes();

    // Ensure our chaining value is all zeros to begin with
    for c in out.iter_mut() {
        *c = 0;
    }

    // First we XOR the IV into the chaining value and encrypt
    let cipher = C::new(key);
    xor_into(out, iv);
    cipher.encrypt_block(out);

    // Now we iterate through all the various data values and make blocks to encrypt
    let block_len = out.len();
    // We will perform n block encryptions, filling this block with the input data
    let mut block = GenericArray::<u8, C::BlockSize>::default();
    let mut block_bytes_filled = 0;

    // The first block starts with input_len || block_len
    // For AES this is 1/2 a block, but for DES this is a full block, so we can always directly copy
    block[..4].copy_from_slice(&input_len_bytes);
    block_bytes_filled += 4;
    block[4..8].copy_from_slice(&output_len_bytes);
    block_bytes_filled += 4;

    // Now we need to fill blocks with the bytes in data, we do this by
    // iterating through the slice
    for byte in data.iter().flat_map(|slice| slice.iter()) {
        // When the block is filled, we should perform an encryption and start again
        if block_bytes_filled == block_len {
            // Actually do the work
            xor_into(out, &block);
            cipher.encrypt_block(out);

            // update internal helpers after encryption
            block_bytes_filled = 0;
        }

        // Now add the next byte to the block to encrypt
        block[block_bytes_filled] = *byte;
        block_bytes_filled += 1; // update the counter
    }

    // check if the block is filled after the last loop
    if block_bytes_filled == block_len {
        xor_into(out, &block);
        cipher.encrypt_block(out);
        block_bytes_filled = 0;
    }

    // Finally we need to append the byte 0x80 followed by zeros for the
    // final block
    block[block_bytes_filled] = 0x80;
    block_bytes_filled += 1;

    // pad with zeros...
    for i in block_bytes_filled..block_len {
        block[i] = 0x00;
    }

    // Perform the final encryption
    xor_into(out, &block);
    cipher.encrypt_block(out);
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
#[cfg(feature = "tdea-ctr")]
pub type TdeaCtrDrbg = super::CtrDrbg<TdesEde3, { 21 + 8 }>;

#[cfg(feature = "aes-ctr")]
pub type AesCtr128Drbg = super::CtrDrbg<Aes128, { 16 + 16 }>;

#[cfg(feature = "aes-ctr")]
pub type AesCtr192Drbg = super::CtrDrbg<Aes192, { 24 + 16 }>;

#[cfg(feature = "aes-ctr")]
pub type AesCtr256Drbg = super::CtrDrbg<Aes256, { 32 + 16 }>;
