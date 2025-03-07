use aes::cipher::{BlockCipher, KeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes192, Aes256};

use crate::{Drbg, SeedError};

pub struct CtrDrbg<C: BlockCipher + KeyInit> {
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

impl<C: BlockCipher + KeyInit> CtrDrbg<C> {
    pub fn new(
        entropy: &[u8],
        nonce: &[u8],
        personalisation_string: &[u8],
        derivation_function: bool,
    ) -> Result<Self, SeedError> {
        let mut key = GenericArray::<u8, C::KeySize>::default();
        let mut value = GenericArray::<u8, C::BlockSize>::default();

        // When a derivation function is used then the entropy input is
        // seed_material = entropy || nonce || personalisation_string
        // which is fed into a derivation function before being used
        // as the value to be processed by ctr_drbg_update
        if derivation_function {
            // TODO: ensure that entropy || nonce || personalisation_string
            // as exactly length BlockSize + KeySize
            let mut seed_material: [u8; 1];
            ctr_df(&[entropy, nonce, personalisation_string], &seed_material);
        }
        // Otherwise seed_material = entropy ^ pad(personalisation_string)
        else {
            if !nonce.is_empty() {
                return Err(SeedError::CounterExhausted); // TODO this should be a new error, lazy
            }
            // TODO assert that entropy has length BlockSize + KeySize and return an error if not

            // Now pad the personalization string
            // TODO: is the best thing here to make something of the right length of all zeros
            // then copy the personalization string into it?
            // I guess seed_material can be made all zeros len seedlen, copy personalization into
            // it and then XOR with entropy below

            // Finally compute
            // seed_material = entropy ^ personalisation_string
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
        ctr_drbg.ctr_drbg_update(&[entropy, nonce, personalisation_string]);
        Ok(ctr_drbg)
    }

    // Auxiliary function in section 10.1.2.2
    fn ctr_drbg_update(&mut self, provided_data: &[&[u8]]) {
        todo!()
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

// Aux function in 10.3.2
// we really want to return this: [u8; C:BlockSize + C:KeySize] or should
// we include this into the input like with hash_df
fn ctr_df<C: BlockCipher + KeyInit>(seed_material: &[&[u8]], out: &mut [u8]) {
    todo!()
}

impl<C: BlockCipher + KeyInit> Drbg for CtrDrbg<C> {
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

#[cfg(feature = "aes-ctr")]
pub type AesCtr128Drbg = super::CtrDrbg<Aes128>;

#[cfg(feature = "aes-ctr")]
pub type AesCtr192Drbg = super::CtrDrbg<Aes192>;

#[cfg(feature = "aes-ctr")]
pub type AesCtr256Drbg = super::CtrDrbg<Aes256>;
