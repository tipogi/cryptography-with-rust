use anyhow::anyhow;
use argon2::{password_hash::{Output, SaltString}, Argon2, PasswordHash, PasswordHasher};
use sha2::{Digest, Sha256, Sha512};

use crate::elements::argon_algorithm::{params_v1, ARGON2_SALT, ARGON_ALGORITHM, ARGON_VERSION};
use base64ct::{Base64, Base64Unpadded, Encoding};

// We will use sha256 algorithm because if we use sha512 algorithm, the hash output
// is 64 bytes. After, when we parse to SaltString, it overpasses the Salt::MAX_LENGTH
//
// TODO: We could split in smaller byte array, just taking the first 32 bytes but I do not know how secure is that
// TODO: Or another option would be to use another crate as `rust-argon2` that accepts a binary array
// for salt as argument
pub fn sha256_hash_to_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let input_hash = hasher.finalize();
    println!(
        "sha256 hash array bytes length is: {:?} bytes",
        input_hash.len()
    );
    // Encode the hash to base64 format. We cannot use that because Salt format would be wrong in some scenarios
    //Base64::encode_string(&input_hash)
    // The problem of that encoding is that it doubles the size of the bytes
    // In our case till 64 bytes
    hex::encode(&input_hash)
}

pub fn sha512_hash_to_base64(input: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(input);
    // sha512 creates a digest of 64 bytes. But it is an array bytes types, not string
    let hash_input = hasher.finalize();
    let base64_input = Base64::encode_string(&hash_input);
    // Create a chunk of 64 length because when we encode to base64, the length increase
    // The reason of that below. Find "BACKGROUND" keyword
    let (chunk, _) = base64_input.split_at(64);
    chunk.to_string()
}

// Hash twice the input: Get the digest of sha512 and hash the password with argon2 function
pub fn hash_input(input: &String) -> anyhow::Result<Output> {
    // That salt length has to be less than salt::MAX_LENGTH
    // In our case is the max: 64 bytes
    let fixed_salt = sha512_hash_to_base64(ARGON2_SALT);
    let salt_string = SaltString::from_b64(&fixed_salt).map_err(|e| anyhow!(e))?;

    let custom_params = params_v1()?;

    let argon2_instance = Argon2::new(ARGON_ALGORITHM, ARGON_VERSION, custom_params);

    let input_hash = argon2_instance
        .hash_password(input.as_bytes(), &salt_string)
        .map_err(|e| anyhow!(e))?;

    // Just for understanding purpose
    //extract_binary_data_from_hash(&input_hash, true);

    let output = input_hash.hash.unwrap();

    Ok(output)
}

fn _extract_binary_data_from_hash(input_hash: &PasswordHash, print_output: bool) {
    let input_hash_str = input_hash.hash.unwrap().to_string();
    if print_output {
        println!("argon2 HASH: {}", input_hash_str);
        println!("bytes: {:?}", input_hash.hash.unwrap().as_bytes());
    }

    // We get the same byte array if we apply base64 unpadded type
    // The length comes from the argon2 hash default value. In our case 32 bytes
    // TODO: the length should be generic
    let as_bytes_conversion: [u8; 32] = input_hash.hash
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();

    // Base64 representation. If we would like to get again the byte conversion of the hash,
    // we have to decode from base64. We cannot apply as_bytes() function because it creates
    // another byte array that does not corresponds to the real one
    let as_string_conversion = input_hash.hash
        .unwrap()
        .to_string();

    if print_output {
        println!(
            "Output trait, byte representation: {:?}",
            as_bytes_conversion
        );
        println!(
            "Output trait, String representation: {:?}",
            as_string_conversion
        );
    }

    // BACKGROUND
    // The confusion about the 32-byte hash being encoded as 43 characters arises from the use of Base64 encoding.
    // Base64 encoding is a method used to convert binary data into a string format that can be easily transmitted or stored.
    // It works by taking 3 bytes of binary data and converting them into 4 characters,
    // where each character represents 6 bits of the original data
    //
    // However, the actual encoded length is 43 characters, which suggests that the last character is a padding character (=)
    // added to make the total length a multiple of 4. This is because Base64 encoding requires the encoded data to be a
    // multiple of 4 characters in length.
    //
    // More info: https://docs.rs/password-hash/0.5.0/password_hash/struct.Output.html

    // NOTE: This is unpadded base64, so you either need to add the character '=' to the end - making it a multiple
    // of 4 characters - or make sure that your base64 decoder can handle unpadded base64

    // TODO: That length, 32, should be base on the length of the hash
    let mut slice_32: [u8; 32] = [0; 32];
    let temporal_slice_for_bytes: &mut [u8] = &mut slice_32;

    // Get the original hash representation in binary
    let byte_data = Base64Unpadded::decode(
        input_hash.hash.unwrap().to_string(),
        temporal_slice_for_bytes,
    )
    .unwrap();

    if print_output {
        println!("hash BYTE data: {:?}", byte_data);
        println!("byte slice LENGTH: {}", byte_data.len());
    }

    // Get the base64 encoded string. It has to be the same as the input_hash
    let mut slice_43: [u8; 43] = [0; 43];
    let temporal_slice_for_str: &mut [u8] = &mut slice_43;
    let back = Base64Unpadded::encode(byte_data, temporal_slice_for_str).unwrap();

    if print_output {
        println!("argon base64 HASH: {:?}", back);
        println!("argon base64 hash LENGTH: {}", back.len());
    }

    _to_base64_url(byte_data);
}

fn _to_base64_url(slice: &[u8]) {
    println!("byte SLICE len(): {:}", slice.len());
    let url = base64_url::encode(slice);
    println!("URL encoded baseURL: {:}", url);
    println!("URL encoded baseURL len(): {:}", url.len());
}
