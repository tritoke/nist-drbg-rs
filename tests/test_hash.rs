use nist_drbg_rs::{Drbg, Sha1Drbg};

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
            algorithm_name: String::new(), // Default to an empty string
            prediction_resistance: false,  // Default to false
            entropy_input_len: 0,          // Default to 0
            nonce_len: 0,                  // Default to 0
            personalization_string_len: 0, // Default to 0
            additional_input_len: 0,       // Default to 0
            returned_bits_len: 0,          // Default to 0
        }
    }
}

#[derive(Debug, Clone)]
pub struct Question {
    entropy_input: Vec<u8>,
    nonce: Vec<u8>,
    personalization_string: Vec<u8>,
    additional_input_1: Vec<u8>,
    additional_input_2: Vec<u8>,
    returned_bits: Vec<u8>,
}

// Implementing the Default trait for Question
impl Default for Question {
    fn default() -> Self {
        Question {
            entropy_input: Vec::new(),
            nonce: Vec::new(),
            personalization_string: Vec::new(),
            additional_input_1: Vec::new(),
            additional_input_2: Vec::new(),
            returned_bits: Vec::new(),
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
            "ReturnedBits" => question.returned_bits = hex::decode(value).unwrap(),
            "AdditionalInput" => {
                if addition_input_seen {
                    question.additional_input_2 = hex::decode(value).unwrap();
                } else {
                    question.additional_input_1 = hex::decode(value).unwrap();
                    addition_input_seen = true;
                }
            }
            _ => panic!("Unexpected key: {name:?}"),
        }
    }
}

fn perform_kat_test(question: &Question, info: &TestInformation) -> bool {
    let mut passed = true;
    // Ensure all lengths match
    passed &= question.entropy_input.len() * 8 == info.entropy_input_len;
    passed &= question.nonce.len() * 8 == info.nonce_len;
    passed &= question.personalization_string.len() * 8 == info.personalization_string_len;
    passed &= question.additional_input_1.len() * 8 == info.additional_input_len;
    passed &= question.additional_input_2.len() * 8 == info.additional_input_len;
    passed &= question.returned_bits.len() * 8 == info.returned_bits_len;

    // buffer to read bytes into
    let mut generated_bytes = vec![0; info.returned_bits_len / 8];

    // Create the correct Drbg from the algorithm name
    match info.algorithm_name.as_str() {
        "SHA-1" => {
            let mut drbg = Sha1Drbg::new(
                &question.entropy_input,
                &question.nonce,
                &question.personalization_string,
            )
            .unwrap();

            // Generate random bytes
            // When no additional bytes are used, we just call the function
            // twice
            if info.additional_input_len == 0 {
                drbg.random_bytes(&mut generated_bytes).unwrap();
                drbg.random_bytes(&mut generated_bytes).unwrap();
            } else {
                drbg.random_bytes_extra(&mut generated_bytes, &question.additional_input_1)
                    .unwrap();
                drbg.random_bytes_extra(&mut generated_bytes, &question.additional_input_2)
                    .unwrap();
            }

            // Ensure the bytes match
            passed &= question.returned_bits == generated_bytes;
        }
        _ => (),
    }
    passed
}

#[test]
fn test_hash_kat() {
    // TODO: generalise this with a name variable for file
    let mut contents =
        std::fs::read_to_string("assets/drbgvectors_no_reseed/Hash_DRBG.rsp").unwrap();
    contents.retain(|c| c != '\r');

    let mut test_passed: bool;
    let mut info_block = TestInformation::default();
    let mut question_block = Question::default();

    for block in contents.split("\n\n") {
        // TODO: do we need this?
        if block.is_empty() {
            continue;
        }

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
            test_passed = perform_kat_test(&question_block, &info_block);
            assert!(test_passed);
        }
    }
}
