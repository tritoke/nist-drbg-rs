#![no_std]

use core::marker::Sized;

pub enum SeedError {
    InsufficientEntropy,
}

pub trait Drbg: Sized {
    fn seed(entropy: &[u8]) -> Result<Self, SeedError>;
    fn reseed(&mut self, entropy: &[u8]) -> Result<(), SeedError>;
    fn random_bytes(&mut self, buf: &mut [u8]);
}
