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

fn test_hash_add() {
    let entropy: &[u8] = &hex::decode("c3ef82ce241f02e4298b118ca4f16225").unwrap();
    let nonce: &[u8] = &hex::decode("15e32abbae6b7433").unwrap();
    let add1: &[u8] = &hex::decode("2b790052f09b364d4a8267a0a7de63b8").unwrap();
    let add2: &[u8] = &hex::decode("2ee0819a671d07b5085cc46aa0e61b56").unwrap();
    let returned_bytes: &[u8] = &hex::decode("5825fa1d1dc33c64cdc8690682eff06039e79508c3af48e880f8227d5f9aaa14b3bc76baee477ebbb5c45547134179223257525e8f3afefb78b59da032f1006d74c9831375a677eab3239c94ebe3f7fa").unwrap();    let mut drbg = Sha1Drbg::new(
        entropy,
        nonce,
        &[]
    ).unwrap();

    let mut buf: [u8; 80] = [0; 80];
    let _ = drbg.random_bytes_extra(&mut buf, add1);
    let _ = drbg.random_bytes_extra(&mut buf, add2);
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

fn test_hmac_add() {
    let entropy: &[u8] = &hex::decode("32c1ca125223de8de569697f92a37c67").unwrap();
    let nonce: &[u8] = &hex::decode("72d4cc4f0544d409").unwrap();
    let add1: &[u8] = &hex::decode("9e98cc8e0f8eb84d1911c1775a5703bb").unwrap();
    let add2: &[u8] = &hex::decode("593aa3a300e5c907a011dd5a3dcd77e2").unwrap();
    let returned_bytes: &[u8] = &hex::decode("942909a9d380aa5d4e3af69093a8fa513ee545b9bf9e1b81c5f30966db3e5cb52f8b1b6fe440d592e5fe4a972c36aa498035e2442f82910c5cd095c7f4b4c7e7555c4669cca481cdfbfda167b5d6f8d5").unwrap();
    let mut drbg = HmacSha1Drbg::new(
        entropy,
        nonce,
        &[]
    ).unwrap();

    let mut buf: [u8; 80] = [0; 80];
    let _ = drbg.random_bytes_extra(&mut buf, &add1);
    let _ = drbg.random_bytes_extra(&mut buf, &add2);
    println!("{}", buf == returned_bytes);
}

fn main() {
    test_hash();
    test_hash_add();
    test_hmac();
    test_hmac_add();
}
