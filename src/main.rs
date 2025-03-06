use nist_drbg_rs::Drbg;
use nist_drbg_rs::Sha1Drbg;
use nist_drbg_rs::HmacSha1Drbg;
use hex;


fn test_hash() {
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

fn test_hmac() {
    let entropy: &[u8] = &hex::decode("e91b63309e93d1d08e30e8d556906875").unwrap();
    let nonce: &[u8] = &hex::decode("f59747c468b0d0da").unwrap();
    let returned_bytes: &[u8] = &hex::decode("b7928f9503a417110788f9d0c2585f8aee6fb73b220a626b3ab9825b7a9facc79723d7e1ba9255e40e65c249b6082a7bc5e3f129d3d8f69b04ed1183419d6c4f2a13b304d2c5743f41c8b0ee73225347").unwrap();
    let mut drbg = HmacSha1Drbg::new(
        entropy,
        nonce,
        &[]
    ).unwrap();

    let mut buf: [u8; 80] = [0; 80];
    let _ = drbg.random_bytes(&mut buf);
    let _ = drbg.random_bytes(&mut buf);
    println!("{}", buf == returned_bytes);
}

fn main() {
    test_hash();
    test_hmac();
}
