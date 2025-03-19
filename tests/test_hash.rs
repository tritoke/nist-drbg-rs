use std::path::Path;

use nist_drbg_rs::{
    Drbg, Sha1Drbg, Sha224Drbg, Sha256Drbg, Sha384Drbg, Sha512_224Drbg, Sha512_256Drbg, Sha512Drbg,
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

// Implementing the Default trait for TestInformation
impl Default for TestInformation {
    fn default() -> Self {
        TestInformation {
            algorithm_name: String::new(),
            prediction_resistance: false,
            entropy_input_len: 0,
            nonce_len: 0,
            personalization_string_len: 0,
            additional_input_len: 0,
            returned_bits_len: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Question {
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

// Implementing the Default trait for Question
impl Default for Question {
    fn default() -> Self {
        Question {
            entropy_input: Vec::new(),
            nonce: Vec::new(),
            personalization_string: Vec::new(),
            entropy_input_reseed: Vec::new(),
            entropy_input_pr_1: Vec::new(),
            entropy_input_pr_2: Vec::new(),
            additional_input_reseed: Vec::new(),
            additional_input_1: Vec::new(),
            additional_input_2: Vec::new(),
            returned_bytes: Vec::new(),
        }
    }
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
        // We don't need to track count
        if name.starts_with("COUNT") {
            continue;
        }
        match name {
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

fn perform_kat_test(question: &Question, info: &TestInformation, reseed: bool) -> bool {
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

    // Create the correct Drbg from the algorithm name
    let mut drbg: Box<dyn Drbg> = match info.algorithm_name.as_str() {
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
        drbg.reseed_extra(&question.entropy_input_pr_1, &question.additional_input_1)
            .unwrap();
        drbg.random_bytes(&mut generated_bytes).unwrap();
    }
    // For all other cases, additional bytes are used in the reseeding itself
    else {
        drbg.random_bytes_extra(&mut generated_bytes, &question.additional_input_1)
            .unwrap();
    }

    // When we use predicition resistence, the additional bytes are used for reseeding
    // and not the generation
    if info.prediction_resistance {
        drbg.reseed_extra(&question.entropy_input_pr_2, &question.additional_input_2)
            .unwrap();
        drbg.random_bytes(&mut generated_bytes).unwrap();
    }
    // For all other cases, additional bytes are used in the reseeding itself
    else {
        drbg.random_bytes_extra(&mut generated_bytes, &question.additional_input_2)
            .unwrap();
    }

    // Ensure the bytes match
    passed &= question.returned_bytes == generated_bytes;

    passed
}

fn run_hash_kat(name: &str) {
    // Whether or not to reseed
    let reseed = name.contains("pr_false");

    let response_file = Path::new("assets").join(name).join("Hash_DRBG.rsp");
    let mut contents = std::fs::read_to_string(response_file).unwrap();
    contents.retain(|c| c != '\r');

    let mut test_passed: bool;
    let mut info_block = TestInformation::default();
    let mut question_block = Question::default();

    for block in contents.split("\n\n") {
        // Ignore the metadata lines
        if block.starts_with('#') {
            continue;
        }
        // Parse the KAT data values for the question
        else if block.starts_with('[') {
            parse_test_information(block, &mut info_block);
        }
        // Otherwise perform a test
        else {
            parse_question_block(block, &mut question_block);
            test_passed = perform_kat_test(&question_block, &info_block, reseed);
            assert!(test_passed);
        }
    }
}

#[test]
fn test_hash_kat_no_reseed() {
    run_hash_kat("drbgvectors_no_reseed");
}

#[test]
fn test_hash_kat_pr_false() {
    run_hash_kat("drbgvectors_pr_false");
}

#[test]
fn test_hash_kat_pr_true() {
    run_hash_kat("drbgvectors_pr_true");
}
