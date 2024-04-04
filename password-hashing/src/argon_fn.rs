use argon2::{password_hash::{Ident, SaltString}, Algorithm, Argon2, Params, PasswordHasher, Version};
use anyhow::anyhow;
use crate::templates;

pub struct ArgonUtils {}

impl ArgonUtils {
    pub fn new(config: templates::EncryptionData, password: &[u8]) -> anyhow::Result<String> {
        let ident = Ident::try_from(config.variant.as_str()).map_err(|e| anyhow!(e))?;
        let algorithm = Algorithm::try_from(ident).map_err(|e| anyhow!(e))?;
        let version = Version::try_from(config.version).map_err(|e| anyhow!(e))?;
        let params = Params::new(
            config.memory_cost,
            config.time_cost,
            config.parallelism_cost,
            None
        ).map_err(|e| anyhow!(e))?;

        // create new argon context
        let argon2_instance = Argon2::new(algorithm, version, params);

        // Create the Salt
        let salt_string = SaltString::from_b64(config.salt.as_str())
            .map_err(|e| anyhow!(e))?;

        // Hash password to PHC string ($argon2id$v=19$...)
        let password_hash = argon2_instance
            .hash_password(
                password,
                &salt_string
            )
            .map_err(|e| anyhow!(e))?
            .to_string();      

        Ok(password_hash)
    }
}