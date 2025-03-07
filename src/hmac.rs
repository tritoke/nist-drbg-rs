use core::marker::PhantomData;

use digest::{KeyInit, generic_array::GenericArray};

use hmac::{Hmac, Mac};

use crate::{Drbg, SeedError};

/// What is the maximum number of calls to Hash_DRBG before the DRBG must be reseeded?
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) table 2
pub const MAX_RESEED_INTERVAL_HMAC: u64 = 1 << 48;

/// What is the recommended number of calls to Hash_DRBG before the DRBG must be reseeded?
///
/// From [NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) Appendix B1
pub const NIST_RESEED_INTERVAL_HMAC: u64 = 100_000;

pub struct HmacDrbg<H: Mac + KeyInit> {
    // key - Value of `seedlen` bits
    key: GenericArray<u8, H::OutputSize>,

    // V - Value of `seedlen` bits
    value: GenericArray<u8, H::OutputSize>,

    // the number of requests for bits received since the last (re)seeding
    reseed_counter: u64,

    // Currently unused:
    // admin bits - not sure about these right now but the standard shows them
    _prediction_resistance_flag: bool, // is this drbg prediction resistant?

    _hasher: PhantomData<H>,
}

impl<H: Mac + KeyInit> HmacDrbg<H> {
    pub fn new(
        entropy: &[u8],
        nonce: &[u8],
        personalization_string: &[u8],
    ) -> Result<Self, SeedError> {
        let mut key = GenericArray::<u8, H::OutputSize>::default();
        let mut value = GenericArray::<u8, H::OutputSize>::default();

        // Default key:   0x00 ... 0x00
        // Default value: 0x01 ... 0x01
        for (ki, vi) in key.iter_mut().zip(value.iter_mut()) {
            *ki = 0u8; // Set key elements to 0x00
            *vi = 1u8; // Set value elements to 0x01
        }

        // Create the object then update
        let mut hmac_drbg = Self {
            key,
            value,
            reseed_counter: 1,
            _prediction_resistance_flag: false,
            _hasher: PhantomData,
        };
        hmac_drbg.hmac_drbg_update(&[entropy, nonce, personalization_string]);
        Ok(hmac_drbg)
    }

    // Auxiliary function in section 10.1.2.2
    fn hmac_drbg_update(&mut self, provided_data: &[&[u8]]) {
        // TODO: handle key error?
        // K = HMAC(K, V || 0x00 || provided_data)
        let mut mac = <H as Mac>::new_from_slice(&self.key).unwrap();
        mac.update(&self.value);
        mac.update(&[0x00]);
        for block in provided_data {
            mac.update(block);
        }
        self.key = mac.finalize().into_bytes();

        // V = HMAC(K, V)
        mac = <H as Mac>::new_from_slice(&self.key).unwrap();
        mac.update(&self.value);
        self.value = mac.finalize().into_bytes();

        if provided_data.is_empty() {
            return;
        }

        // K = HMAC(K, V || 0x01 || provided_data)
        mac = <H as Mac>::new_from_slice(&self.key).unwrap();
        mac.update(&self.value);
        mac.update(&[0x01]);
        for block in provided_data {
            mac.update(block);
        }
        self.key = mac.finalize().into_bytes();

        // V = HMAC(K, V)
        mac = <H as Mac>::new_from_slice(&self.key).unwrap();
        mac.update(&self.value);
        self.value = mac.finalize().into_bytes();
    }

    fn reseed_core(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        match additional_input {
            Some(data) => self.hmac_drbg_update(&[entropy, data]),
            None => self.hmac_drbg_update(&[entropy]),
        }
        self.reseed_counter = 1;

        Ok(())
    }

    fn random_bytes_core(
        &mut self,
        buf: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), SeedError> {
        if self.reseed_counter > NIST_RESEED_INTERVAL_HMAC {
            return Err(SeedError::CounterExhausted);
        }

        // If additional_input is given, run HMAC_update
        if let Some(additional_input) = additional_input {
            self.hmac_drbg_update(&[additional_input])
        }

        // The random bytes we return are the output of repeatedly
        // computing V = HMAC(K, V)

        let bufsz = buf.len();
        let hashsz = self.value.len(); // Seems like a dumb hack
        let m = bufsz.div_ceil(hashsz);

        for i in 0..m {
            // Seems silly making this over and over
            let mut mac = <H as Mac>::new_from_slice(&self.key).unwrap();
            mac.update(&self.value);
            self.value = mac.finalize().into_bytes();

            // buffer = buffer || HMAC(K, V)
            let lower = i * hashsz;
            let upper = (i + 1) * hashsz;
            if upper < buf.len() {
                buf[lower..upper].copy_from_slice(&self.value);
            } else {
                buf[lower..].copy_from_slice(&self.value[..bufsz - lower]);
            }
        }

        // TODO this is gross and should be handled in the first check
        if let Some(additional_input) = additional_input {
            self.hmac_drbg_update(&[additional_input])
        } else {
            self.hmac_drbg_update(&[])
        }
        self.reseed_counter += 1;

        Ok(())
    }
}

impl<H: Mac + KeyInit> Drbg for HmacDrbg<H> {
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

#[cfg(feature = "hmac_sha1")]
pub type HmacSha1Drbg = super::HmacDrbg<Hmac<sha1::Sha1>>;

#[cfg(feature = "hmac_sha2")]
pub type HmacSha224Drbg = super::HmacDrbg<Hmac<sha2::Sha224>>;

#[cfg(feature = "hmac_sha2")]
pub type HmacSha512_224Drbg = super::HmacDrbg<Hmac<sha2::Sha512_224>>;

#[cfg(feature = "hmac_sha2")]
pub type HmacSha256Drbg = super::HmacDrbg<Hmac<sha2::Sha256>>;

#[cfg(feature = "hmac_sha2")]
pub type HmacSha512_256Drbg = super::HmacDrbg<Hmac<sha2::Sha512_256>>;

#[cfg(feature = "hmac_sha2")]
pub type HmacSha384Drbg = super::HmacDrbg<Hmac<sha2::Sha384>>;

#[cfg(feature = "hmac_sha2")]
pub type HmacSha512Drbg = super::HmacDrbg<Hmac<sha2::Sha512>>;
