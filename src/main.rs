use nist_drbg_rs::Drbg;
use nist_drbg_rs::Sha256Drbg;
use hex;

/*
From the KAT

[SHA-256]
[PredictionResistance = False]
[EntropyInputLen = 256]
[NonceLen = 128]
[PersonalizationStringLen = 0]
[AdditionalInputLen = 0]
[ReturnedBitsLen = 1024]

COUNT = 0
EntropyInput = a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb
Nonce = 8581f9317517276e06e9607ddbcbcc2e
PersonalizationString = 
AdditionalInput = 
AdditionalInput = 
ReturnedBits = d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80daaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febdc343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51ccde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df
*/

fn main() {
    let entropy: &[u8] = &hex::decode("a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb").unwrap();
    let nonce: &[u8] = &hex::decode("8581f9317517276e06e9607ddbcbcc2e").unwrap();
    let returned_bytes: &[u8] = &hex::decode("d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80daaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febdc343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51ccde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df").unwrap();
    let mut drbg = Sha256Drbg::new(
        entropy,
        nonce,
        &[]
    ).unwrap();

    let mut buf: [u8; 128] = [0; 128];
    let _ = drbg.random_bytes(&mut buf);
    println!("{}", buf == returned_bytes);
    println!("{}", hex::encode(buf));
    println!("{}", hex::encode(returned_bytes));
}
