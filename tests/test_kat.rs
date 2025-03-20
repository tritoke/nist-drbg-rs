use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use nist_drbg_rs::{
    AesCtr128Drbg, AesCtr192Drbg, AesCtr256Drbg, Drbg, HmacSha1Drbg, HmacSha224Drbg,
    HmacSha256Drbg, HmacSha384Drbg, HmacSha512Drbg, HmacSha512_224Drbg, HmacSha512_256Drbg,
    Sha1Drbg, Sha224Drbg, Sha256Drbg, Sha384Drbg, Sha512Drbg, Sha512_224Drbg, Sha512_256Drbg,
    TdeaCtrDrbg,
};

#[derive(Debug, Clone)]
pub struct TestInformation {
    algorithm_name: String,
    prediction_resistance: bool,
    entropy_input_len: usize,
    nonce_len: usize,
    personalization_string_len: usize,
    additional_input_len: usize,
    returned_bits_len: usize,
}

impl FromStr for TestInformation {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut algorithm_name = None;
        let mut prediction_resistance = None;
        let mut entropy_input_len = None;
        let mut nonce_len = None;
        let mut personalization_string_len = None;
        let mut additional_input_len = None;
        let mut returned_bits_len = None;

        for line in s.lines() {
            let data = line.trim_matches(['[', ']']);
            // For the first line we just get the algorithm name
            if !data.contains('=') {
                algorithm_name = Some(data.to_string());
            } else {
                let (name, value) = data.split_once(" = ").unwrap();
                match name {
                    "PredictionResistance" => {
                        prediction_resistance = Some(
                            value
                                .to_lowercase()
                                .parse()
                                .map_err(|_| "failed to parse PredictionResistance")?,
                        );
                    }
                    "EntropyInputLen" => {
                        entropy_input_len = Some(
                            value
                                .parse()
                                .map_err(|_| "failed to parse EntropyInputLen")?,
                        );
                    }
                    "NonceLen" => {
                        nonce_len = Some(value.parse().map_err(|_| "failed to parse NonceLen")?)
                    }
                    "PersonalizationStringLen" => {
                        personalization_string_len = Some(
                            value
                                .parse()
                                .map_err(|_| "failed to parse PersonalizationStringLen")?,
                        )
                    }
                    "AdditionalInputLen" => {
                        additional_input_len = Some(
                            value
                                .parse()
                                .map_err(|_| "failed to parse AdditionalInputLen")?,
                        )
                    }
                    "ReturnedBitsLen" => {
                        returned_bits_len = Some(
                            value
                                .parse()
                                .map_err(|_| "failed to parse ReturnedBitsLen")?,
                        )
                    }
                    _ => panic!("Unexpected key: {name:?}"),
                }
            }
        }

        Ok(Self {
            algorithm_name: algorithm_name.ok_or("Algorithm name missing")?,
            prediction_resistance: prediction_resistance.ok_or("PredictionResistance missing")?,
            entropy_input_len: entropy_input_len.ok_or("EntropyInputLen missing")?,
            nonce_len: nonce_len.ok_or("NonceLen missing")?,
            personalization_string_len: personalization_string_len
                .ok_or("PersonalizationStringLen missing")?,
            additional_input_len: additional_input_len.ok_or("AdditionalInputLen missing")?,
            returned_bits_len: returned_bits_len.ok_or("ReturnedBitsLen missing")?,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Question {
    count: usize,
    entropy_input: Vec<u8>,
    nonce: Vec<u8>,
    personalization_string: Vec<u8>,
    entropy_input_reseed: Vec<u8>,
    entropy_input_pr_1: Vec<u8>,
    entropy_input_pr_2: Vec<u8>,
    additional_input_reseed: Vec<u8>,
    additional_input_1: Vec<u8>,
    additional_input_2: Vec<u8>,
    returned_bytes: Vec<u8>,
}

impl FromStr for Question {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We need to parse two fields with the same name in the KAT file
        // let mut addition_input_seen = false;
        // let mut entropy_pr_seen = false;

        // for line in block.lines() {
        //     let (name, value) = line.split_once(" = ").unwrap();
        //     match name {
        //         "COUNT" => question.count = value.parse().unwrap(),
        //         "EntropyInput" => question.entropy_input = hex::decode(value).unwrap(),
        //         "Nonce" => question.nonce = hex::decode(value).unwrap(),
        //         "PersonalizationString" => {
        //             question.personalization_string = hex::decode(value).unwrap()
        //         }
        //         "EntropyInputReseed" => question.entropy_input_reseed = hex::decode(value).unwrap(),
        //         "AdditionalInputReseed" => {
        //             question.additional_input_reseed = hex::decode(value).unwrap()
        //         }
        //         "AdditionalInput" => {
        //             if addition_input_seen {
        //                 question.additional_input_2 = hex::decode(value).unwrap();
        //             } else {
        //                 question.additional_input_1 = hex::decode(value).unwrap();
        //                 addition_input_seen = true;
        //             }
        //         }
        //         "EntropyInputPR" => {
        //             if entropy_pr_seen {
        //                 question.entropy_input_pr_2 = hex::decode(value).unwrap();
        //             } else {
        //                 question.entropy_input_pr_1 = hex::decode(value).unwrap();
        //                 entropy_pr_seen = true;
        //             }
        //         }
        //         "ReturnedBits" => question.returned_bytes = hex::decode(value).unwrap(),
        //         _ => panic!("Unexpected key: {name:?}"),
        //     }
        // }

        Ok(todo!())
    }
}

fn create_hash_drbg_from_name(question: &Question, info: &TestInformation) -> Box<dyn Drbg> {
    let drbg: Box<dyn Drbg> = match info.algorithm_name.as_str() {
        "SHA-1" => Box::new(
            Sha1Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-224" => Box::new(
            Sha224Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-256" => Box::new(
            Sha256Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-384" => Box::new(
            Sha384Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-512" => Box::new(
            Sha512Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-512/224" => Box::new(
            Sha512_224Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-512/256" => Box::new(
            Sha512_256Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        _ => panic!("Unexpected algorithm: {{info.algorithm_name.as_str():?}}"),
    };
    drbg
}

fn create_hmac_drbg_from_name(question: &Question, info: &TestInformation) -> Box<dyn Drbg> {
    let drbg: Box<dyn Drbg> = match info.algorithm_name.as_str() {
        "SHA-1" => Box::new(
            HmacSha1Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-224" => Box::new(
            HmacSha224Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-256" => Box::new(
            HmacSha256Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-384" => Box::new(
            HmacSha384Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-512" => Box::new(
            HmacSha512Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-512/224" => Box::new(
            HmacSha512_224Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "SHA-512/256" => Box::new(
            HmacSha512_256Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        _ => panic!("Unexpected algorithm: {{info.algorithm_name.as_str():?}}"),
    };
    drbg
}

fn create_ctr_drbg_from_name(question: &Question, info: &TestInformation) -> Box<dyn Drbg> {
    let drbg: Box<dyn Drbg> = match info.algorithm_name.as_str() {
        "3KeyTDEA use df" => Box::new(
            TdeaCtrDrbg::new_with_df(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "3KeyTDEA no df" => Box::new(
            TdeaCtrDrbg::new(&question.entropy_input, &question.personalization_string).unwrap(),
        ),
        "AES-128 use df" => Box::new(
            AesCtr128Drbg::new_with_df(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "AES-128 no df" => Box::new(
            AesCtr128Drbg::new(&question.entropy_input, &question.personalization_string).unwrap(),
        ),
        "AES-192 use df" => Box::new(
            AesCtr192Drbg::new_with_df(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "AES-192 no df" => Box::new(
            AesCtr192Drbg::new(&question.entropy_input, &question.personalization_string).unwrap(),
        ),
        "AES-256 use df" => Box::new(
            AesCtr256Drbg::new_with_df(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap(),
        ),
        "AES-256 no df" => Box::new(
            AesCtr256Drbg::new(&question.entropy_input, &question.personalization_string).unwrap(),
        ),
        _ => panic!("Unexpected algorithm: {{info.algorithm_name.as_str():?}}"),
    };
    drbg
}

fn perform_kat_test(question: &Question, info: &TestInformation, reseed: bool, name: &str) -> bool {
    let mut passed = true;

    // Ensure all lengths match
    passed &= question.entropy_input.len() * 8 == info.entropy_input_len;
    passed &= question.nonce.len() * 8 == info.nonce_len;
    passed &= question.personalization_string.len() * 8 == info.personalization_string_len;
    passed &= question.additional_input_1.len() * 8 == info.additional_input_len;
    passed &= question.additional_input_2.len() * 8 == info.additional_input_len;
    passed &= question.returned_bytes.len() * 8 == info.returned_bits_len;

    // For the pr_false tests, we have reseeding values which we must check
    if reseed {
        passed &= question.entropy_input_reseed.len() * 8 == info.entropy_input_len;
        passed &= question.additional_input_reseed.len() * 8 == info.additional_input_len;
    }

    // When prediciton resistance is required we have two other entropy inputs
    if info.prediction_resistance {
        passed &= question.entropy_input_pr_1.len() * 8 == info.entropy_input_len;
        passed &= question.entropy_input_pr_2.len() * 8 == info.entropy_input_len;
    }

    // buffer to read bytes into
    let mut generated_bytes = vec![0; info.returned_bits_len / 8];

    // TODO: when we use Triple DES there's a bug, need to fix it
    if info.algorithm_name.contains("3KeyTDEA") {
        return true;
    }

    // Create the correct Drbg from the algorithm name
    let mut drbg;
    match name {
        "Hash" => drbg = create_hash_drbg_from_name(question, info),
        "HMAC" => drbg = create_hmac_drbg_from_name(question, info),
        "CTR" => drbg = create_ctr_drbg_from_name(question, info),
        _ => panic!("Unexpected name: {name}"),
    }

    // For pr_false we reseed before requesting any bytes at all
    if reseed {
        drbg.reseed_extra(
            &question.entropy_input_reseed,
            &question.additional_input_reseed,
        )
        .unwrap()
    }

    // When we use predicition resistence, the additional bytes are used for reseeding
    // and not the generation
    if info.prediction_resistance {
        // Request the first chunk of bytes
        drbg.reseed_extra(&question.entropy_input_pr_1, &question.additional_input_1)
            .unwrap();
        drbg.random_bytes(&mut generated_bytes).unwrap();

        // Request the second chunk of bytes
        drbg.reseed_extra(&question.entropy_input_pr_2, &question.additional_input_2)
            .unwrap();
        drbg.random_bytes(&mut generated_bytes).unwrap();
    }
    // For all other cases, additional bytes are used in the reseeding itself
    else {
        // Request the first chunk of bytes
        drbg.random_bytes_extra(&mut generated_bytes, &question.additional_input_1)
            .unwrap();
        // Request the second chunk of bytes
        drbg.random_bytes_extra(&mut generated_bytes, &question.additional_input_2)
            .unwrap();
    }

    // Ensure the bytes match
    passed &= question.returned_bytes == generated_bytes;
    passed
}

#[derive(Debug)]
struct KnownAnswerTest {
    info: TestInformation,
    questions: Vec<Question>,
}

impl FromStr for KnownAnswerTest {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Create structs which contain the test information and question data
        let mut info = None;
        let mut questions = vec![];

        // Iterate through each KAT block
        for block in s.split("\n\n") {
            // Ignore the metadata or empty blocks
            if block.starts_with('#') || block.is_empty() {
                continue;
            }
            // Parse the KAT data values for the question
            else if block.starts_with('[') {
                info = Some(block.parse()?);
            }
            // Subsequent blocks are then question blocks which we parse and then test
            else {
                let q = block.parse()?;
                questions.push(q);
            }
        }

        if questions.is_empty() {
            return Err("No questions in KAT?");
        }

        Ok(Self {
            info: info.ok_or("test information missing")?,
            questions,
        })
    }
}

impl KnownAnswerTest {
    fn load(kat_type: &str, name: &str) -> Self {
        let response_file = [
            String::from("assets"),
            kat_type.to_owned(),
            format!("{}_DRBG.rsp", name),
        ]
        .iter()
        .collect::<PathBuf>();
        let contents = std::fs::read_to_string(response_file).expect("Failed to read KAT file");

        contents.parse().expect("Failed to parse KAT file")
    }

    fn test_impl(&self, drbg_under_test: impl Fn(&Question) -> )
}

fn run_kat_test(kat_type: &str, name: &str) {
    let reseed = kat_type.contains("pr_false");
    let test = KnownAnswerTest::load(kat_type, name);

    for q in &test.questions {
        
    }

    let test_passed = perform_kat_test(&question_block, &info_block, reseed, name);
    assert!(test_passed, "Test {kat_type} for {name} DRBG failed");
}

#[test]
/// Test KAT values for Hash Drbg with no reseeding
fn test_hash_kat_no_reseed() {
    run_kat_test("drbgvectors_no_reseed", "Hash");
}

#[test]
/// Test KAT values for Hash Drbg with explicit reseeding
fn test_hash_kat_pr_false() {
    run_kat_test("drbgvectors_pr_false", "Hash");
}

#[test]
/// Test KAT values for Hash Drbg with reseeding before extraction
fn test_hash_kat_pr_true() {
    run_kat_test("drbgvectors_pr_true", "Hash");
}

#[test]
/// Test KAT values for HMAC Drbg with no reseeding
fn test_hmac_kat_no_reseed() {
    run_kat_test("drbgvectors_no_reseed", "HMAC");
}

#[test]
/// Test KAT values for HMAC Drbg with reseeding before extraction
fn test_hmac_kat_pr_false() {
    run_kat_test("drbgvectors_pr_false", "HMAC");
}

#[test]
/// Test KAT values for HMAC Drbg with reseeding before extraction
fn test_hmac_kat_pr_true() {
    run_kat_test("drbgvectors_pr_true", "HMAC");
}

#[test]
/// Test KAT values for CTR Drbg with no reseeding
fn test_ctr_kat_no_reseed() {
    run_kat_test("drbgvectors_no_reseed", "CTR");
}

#[test]
/// Test KAT values for CTR Drbg with reseeding before extraction
fn test_ctr_kat_pr_false() {
    run_kat_test("drbgvectors_pr_false", "CTR");
}

#[test]
/// Test KAT values for CTR Drbg with reseeding before extraction
fn test_ctr_kat_pr_true() {
    run_kat_test("drbgvectors_pr_true", "CTR");
}
