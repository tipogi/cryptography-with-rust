use anyhow::anyhow;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use password_hashing::{
    argon_fn::ArgonUtils, 
    templates::EncryptionData
};

fn main() -> anyhow::Result<()>{
    let plain_password = "HeLl0RustycRysti;)".as_bytes();
    
    let argon_password = hashed_password_with_argon(plain_password)?;
    
    let parsed_hash = PasswordHash::new(&argon_password).map_err(|e| anyhow!(e))?;
    
    println!(
        "authentication result: {}",
        Argon2::default()
            .verify_password(plain_password, &parsed_hash)
            .is_ok()
    );

    Ok(())
}

fn hashed_password_with_argon(password: &[u8]) -> anyhow::Result<String>{
    let encryption_data = EncryptionData::init()?;

    ArgonUtils::new(encryption_data, password)

    
}
