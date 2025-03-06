use core::marker::PhantomData;

use digest::{Digest, OutputSizeUser};

use hmac::{Hmac, Mac};

use crate::{Drbg, SeedError};

// Jack: we probably don't need OUTLEN as we can get it from Digest itself?

pub struct HmacDrbg<H: Digest, const OUTLEN: usize> {
    // key - Value of `seedlen` bits
    key: [u8; OUTLEN],

    // V - Value of `seedlen` bits
    value: [u8; OUTLEN],

    // the number of requests for bits received since the last (re)seeding
    reseed_counter: u64,

    // Currently unused:
    // admin bits - not sure about these right now but the standard shows them
    _prediction_resistance_flag: bool, // is this drbg prediction resistant?

    _hasher: PhantomData<H>,
}

impl<H: Digest, const OUTLEN: usize> HmacDrbg<H, OUTLEN> {
    pub fn new(
        entropy: &[u8],
        nonce: &[u8],
        personalisation_string: &[u8],
    ) -> Result<Self, SeedError> {
        let key = [0u8; OUTLEN];
        let value = [01u8; OUTLEN];

        // Create the object then update
        let mut hmac_drbg = Self{ 
            key,
            value,
            reseed_counter: 1,
            _prediction_resistance_flag: false,
            _hasher: PhantomData,
        };
        hmac_drbg.hmac_drbg_update(&[entropy, nonce, personalisation_string]);
        
        Ok(hmac_drbg)
        
    }

    // Auxiliary function in section 10.1.2.2
    fn hmac_drbg_update(self, provided_data: &[&[u8]])
    {
        // K = HMAC(K, V || 0x00 || provided_data)
        let mut mac = Hmac::<H>::new_from_slice(&self.key);
        mac.update(self.value);
        mac.update([0x00]);
        for block in provided_data {
            mac.update(block);
        }
        self.key = mac.finalize();

        // V = HMAC(K, V)
        mac = Hmac::<H>::new_from_slice(self.key);
        mac.update(self.value);
        self.value = mac.finalize();

        if provided_data.len() == 0 {
            return;
        }

        // K = HMAC(K, V || 0x00 || provided_data)
        mac = Hmac::<H>::new_from_slice(&self.key);
        mac.update(self.value);
        mac.update([0x01]);
        for block in provided_data {
            mac.update(block);
        }
        self.key = mac.finalize();

        // V = HMAC(K, V)
        mac = Hmac::<H>::new_from_slice(self.key);
        mac.update(self.value);
        self.value = mac.finalize();
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



impl<H: Digest, const SEEDLEN: usize> Drbg for HmacDrbg<H, SEEDLEN> {
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
pub type Sha1Drbg = super::HmacDrbg<sha1::Sha1, { 160 / 8 }>;

#[cfg(feature = "hmac_sha2")]
pub type Sha224Drbg = super::HmacDrbg<sha2::Sha224, { 224 / 8 }>;

#[cfg(feature = "hmac_sha2")]
pub type Sha512_224Drbg = super::HmacDrbg<sha2::Sha512_224, { 224 / 8 }>;

#[cfg(feature = "hmac_sha2")]
pub type Sha256Drbg = super::HmacDrbg<sha2::Sha256, { 256 / 8 }>;

#[cfg(feature = "hmac_sha2")]
pub type Sha512_256Drbg = super::HmacDrbg<sha2::Sha512_256, { 256 / 8 }>;

#[cfg(feature = "hmac_sha2")]
pub type Sha384Drbg = super::HmacDrbg<sha2::Sha384, { 384 / 8 }>;

#[cfg(feature = "hmac_sha2")]
pub type Sha512Drbg = super::HmacDrbg<sha2::Sha512, { 512 / 8 }>;
