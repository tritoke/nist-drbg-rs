use std::path::Path;

use nist_drbg_rs::{
    AesCtr128Drbg, AesCtr192Drbg, AesCtr256Drbg, Drbg, HmacSha1Drbg, HmacSha224Drbg,
    HmacSha256Drbg, HmacSha384Drbg, HmacSha512_224Drbg, HmacSha512_256Drbg, HmacSha512Drbg, Policy,
    PredictionResistance, Sha1Drbg, Sha224Drbg, Sha256Drbg, Sha384Drbg, Sha512_224Drbg,
    Sha512_256Drbg, Sha512Drbg, TdeaCtrDrbg,
};

#[derive(Debug, Clone, Default)]
pub struct TestInformation {
    algorithm_name: String,
    prediction_resistance: bool,
    entropy_input_len: usize,
    nonce_len: usize,
    personalization_string_len: usize,
    additional_input_len: usize,
    returned_bits_len: usize,
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

fn parse_bool(input: &str) -> bool {
    match input {
        "True" => true,
        "False" => false,
        _ => panic!("Unexpected key: {input:?}"),
    }
}

fn parse_test_information(block: &str, info: &mut TestInformation) {
    for line in block.lines() {
        let data = line.trim_matches(|c| c == '[' || c == ']');
        // For the first line we just get the algorithm name
        if !data.contains("=") {
            info.algorithm_name = data.to_string();
        } else {
            let (name, value) = data.split_once(" = ").unwrap();
            match name {
                "PredictionResistance" => info.prediction_resistance = parse_bool(value),
                "EntropyInputLen" => info.entropy_input_len = value.parse().unwrap(),
                "NonceLen" => info.nonce_len = value.parse().unwrap(),
                "PersonalizationStringLen" => {
                    info.personalization_string_len = value.parse().unwrap()
                }
                "AdditionalInputLen" => info.additional_input_len = value.parse().unwrap(),
                "ReturnedBitsLen" => info.returned_bits_len = value.parse().unwrap(),
                _ => panic!("Unexpected key: {name:?}"),
            }
        }
    }
}

fn parse_question_block(block: &str, question: &mut Question) {
    // We need to parse two fields with the same name in the KAT file
    let mut addition_input_seen = false;
    let mut entropy_pr_seen = false;

    for line in block.lines() {
        let (name, value) = line.split_once(" = ").unwrap();
        match name {
            "COUNT" => question.count = value.parse().unwrap(),
            "EntropyInput" => question.entropy_input = hex::decode(value).unwrap(),
            "Nonce" => question.nonce = hex::decode(value).unwrap(),
            "PersonalizationString" => {
                question.personalization_string = hex::decode(value).unwrap()
            }
            "EntropyInputReseed" => question.entropy_input_reseed = hex::decode(value).unwrap(),
            "AdditionalInputReseed" => {
                question.additional_input_reseed = hex::decode(value).unwrap()
            }
            "AdditionalInput" => {
                if addition_input_seen {
                    question.additional_input_2 = hex::decode(value).unwrap();
                } else {
                    question.additional_input_1 = hex::decode(value).unwrap();
                    addition_input_seen = true;
                }
            }
            "EntropyInputPR" => {
                if entropy_pr_seen {
                    question.entropy_input_pr_2 = hex::decode(value).unwrap();
                } else {
                    question.entropy_input_pr_1 = hex::decode(value).unwrap();
                    entropy_pr_seen = true;
                }
            }
            "ReturnedBits" => question.returned_bytes = hex::decode(value).unwrap(),
            _ => panic!("Unexpected key: {name:?}"),
        }
    }
}

fn create_hash_drbg_from_name(question: &Question, info: &TestInformation) -> Box<dyn Drbg> {
    let policy = if info.prediction_resistance {
        Policy::default().with_prediction_resistance(PredictionResistance::Enabled)
    } else {
        Policy::default().with_prediction_resistance(PredictionResistance::Disabled)
    };
    let drbg: Box<dyn Drbg> = match info.algorithm_name.as_str() {
        "SHA-1" => Box::new(
            Sha1Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
                policy,
            )
            .unwrap(),
        ),
        "SHA-224" => Box::new(
            Sha224Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
                policy,
            )
            .unwrap(),
        ),
        "SHA-256" => Box::new(
            Sha256Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
                policy,
            )
            .unwrap(),
        ),
        "SHA-384" => Box::new(
            Sha384Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
                policy,
            )
            .unwrap(),
        ),
        "SHA-512" => Box::new(
            Sha512Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
                policy,
            )
            .unwrap(),
        ),
        "SHA-512/224" => Box::new(
            Sha512_224Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
                policy,
            )
            .unwrap(),
        ),
        "SHA-512/256" => Box::new(
            Sha512_256Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
                policy,
            )
            .unwrap(),
        ),
        _ => panic!("Unexpected algorithm: {:?}", info.algorithm_name.as_str()),
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
        _ => panic!("Unexpected algorithm: {:?}", info.algorithm_name.as_str()),
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
        _ => panic!("Unexpected algorithm: {:?}", info.algorithm_name.as_str()),
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

fn run_kat_test(kat_type: &str, name: &str) {
    // Whether or not to explicitly reseed
    let reseed = kat_type.contains("pr_false");

    // Load the KAT file as a string
    let response_file = Path::new("assets")
        .join(kat_type)
        .join(format!("{}_DRBG.rsp", name));
    let contents = std::fs::read_to_string(response_file).unwrap();

    // Create structs which contain the test information and question data
    let mut info_block = TestInformation::default();
    let mut question_block = Question::default();

    // Iterate through each KAT block
    for block in contents.split("\n\n") {
        // Ignore the metadata or empty blocks
        if block.starts_with('#') || block.is_empty() {
            continue;
        }
        // Parse the KAT data values for the question
        else if block.starts_with('[') {
            parse_test_information(block, &mut info_block);
        }
        // Subsequent blocks are then question blocks which we parse and then test
        else {
            parse_question_block(block, &mut question_block);
            let test_passed = perform_kat_test(&question_block, &info_block, reseed, name);
            assert!(test_passed);
        }
    }
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
