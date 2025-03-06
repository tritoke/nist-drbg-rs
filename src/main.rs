use nist_drbg_rs::Drbg;
use nist_drbg_rs::Sha1Drbg;
use hex;


fn main() {
    let entropy: &[u8] = &hex::decode("136cf1c174e5a09f66b962d994396525").unwrap();
    let nonce: &[u8] = &hex::decode("fff1c6645f19231f").unwrap();
    let returned_bytes: &[u8] = &hex::decode("0e28130fa5ca11edd3293ca26fdb8ae1810611f78715082ed3841e7486f16677b28e33ffe0b93d98ba57ba358c1343ab2a26b4eb7940f5bc639384641ee80a25140331076268bd1ce702ad534dda0ed8").unwrap();
    let mut drbg = Sha1Drbg::new(
        entropy,
        nonce,
        &[]
    ).unwrap();

    let mut buf: [u8; 80] = [0; 80];
    let _ = drbg.random_bytes(&mut buf);
    let _ = drbg.random_bytes(&mut buf);
    println!("{}", buf == returned_bytes);
}
