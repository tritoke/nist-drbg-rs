use core::marker::PhantomData;

use digest::{generic_array::GenericArray, Digest, InnerInit, KeyInit};

use hmac::{Hmac, Mac};

use crate::{Drbg, SeedError};

// Jack: we probably don't need OUTLEN as we can get it from Digest itself?

pub struct HmacDrbg<H:  Mac + KeyInit + InnerInit> {
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

impl<H: Mac + KeyInit + InnerInit> HmacDrbg<H> {
    pub fn new(
        entropy: &[u8],
        nonce: &[u8],
        personalisation_string: &[u8],
    ) -> Result<Self, SeedError> {
        let mut key = GenericArray::<u8, H::OutputSize>::default();
        let mut value = GenericArray::<u8, H::OutputSize>::default();

        // Default key:   0x00 ... 0x00
        // Default value: 0x01 ... 0x01
        // TODO: is this really how to do this?!
        for i in 0..key.as_slice().len() {
            key[i] = 0x0;
            value[i] = 0x1;
        }

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
    fn hmac_drbg_update(&mut self, provided_data: &[&[u8]])
    {
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

        if provided_data.len() == 0 {
            return;
        }

        // K = HMAC(K, V || 0x00 || provided_data)
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
    ) {
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


#[cfg(feature = "hmac_sha1")]
pub type Sha1Drbg = super::HmacDrbg<Hmac<sha1::Sha1>>;

#[cfg(feature = "hmac_sha2")]
pub type Sha224Drbg = super::HmacDrbg<Hmac<sha2::Sha224>>;

#[cfg(feature = "hmac_sha2")]
pub type Sha512_224Drbg = super::HmacDrbg<Hmac<sha2::Sha512_224>>;

#[cfg(feature = "hmac_sha2")]
pub type Sha256Drbg = super::HmacDrbg<Hmac<sha2::Sha256>>;

#[cfg(feature = "hmac_sha2")]
pub type Sha512_256Drbg = super::HmacDrbg<Hmac<sha2::Sha512_256>>;

#[cfg(feature = "hmac_sha2")]
pub type Sha384Drbg = super::HmacDrbg<Hmac<sha2::Sha384>>;

#[cfg(feature = "hmac_sha2")]
pub type Sha512Drbg = super::HmacDrbg<Hmac<sha2::Sha512>>;
