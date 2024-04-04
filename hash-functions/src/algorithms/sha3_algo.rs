use base64ct::{Base64, Encoding};
use sha3::{ Digest, Sha3_256 };

pub fn hash3_encryption_algorithm() {
    let message = b"Time to hide in a cave mr Crab!!";
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    let hashed_message = hasher.finalize();
    println!("{:?}", hashed_message);

    // Hashed array format to base64
    // !! Activate `alloc` feature in the crate
    let base64_hash = Base64::encode_string(&hashed_message);
    println!("Base64-encoded hash: {}", base64_hash);

    // hashed array format to HEX
    let hex_hash = hex::encode(&hashed_message);
    println!("HEX-encoded hash: {}", hex_hash);
}
