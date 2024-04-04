use std::str;

use sha2::{Digest, Sha256};
use base64ct::{ Base64, Encoding };

pub fn hash2_encryption_algorithm() {
    // Byte slice representation of the string slice when we add b as a prefix
    let message = b"Time to hide in a cave mr Crab!!";
    println!("message byte array => {:?}", message);
    let mut hasher = Sha256::new();
    hasher.update(message);
    // Has type GenericArray<u8, U32>, which is a generic alternative to [u8; 32]
    let message_hash = hasher.finalize();
    println!("Binary hash => {:?}", message_hash);

    // NOTE: We cannot do that parsing because the binary hash does not have uft8 formating
    match str::from_utf8(&message_hash) {
        Ok(hashed) => println!("{}", hashed),
        Err(error_str) => println!("ERROR: {}", error_str)
    };

    let binary_hash = [216, 137];
    println!("CUSTOM Binary hash => {:?}", str::from_utf8(&binary_hash).unwrap());

    // Hashed array format to base64
    // !! Activate `alloc` feature in the crate
    let base64_hash = Base64::encode_string(&message_hash);
    println!("Base64-encoded hash: {}", base64_hash);

    // hashed array format to HEX
    let hex_hash = hex::encode(&message_hash);
    println!("HEX-encoded hash: {}", hex_hash);
}

