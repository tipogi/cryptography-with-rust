use std::env;
use anyhow::anyhow;

#[derive(Debug)]
pub struct EncryptionData {
    pub variant: String,
    pub salt: String,
    pub version: u32,
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism_cost: u32,
}

const PATH: &str = "./password-hashing/.env";

impl EncryptionData {
    pub fn init() -> anyhow::Result<EncryptionData> {

        dotenv::from_path(PATH).ok();

        let salt = env::var_os("ARGON2_PHC_SALT")
            .expect("ARGON2_PHC_SALT is undefined.")
            .into_string()
            .map_err(|_| anyhow!("ARGON2_PHC_SALT is invalid value."))?;

        let variant = env::var_os("ARGON2_PHC_VARIANT")
            .expect("ARGON2_PHC_VARIANT is undefined.")
            .into_string()
            .map_err(|_| anyhow!("ARGON2_PHC_VARIANT is invalid value."))?;

        let version = env::var_os("ARGON2_PHC_VERSION")
            .expect("ARGON2_PHC_VERSION is undefined.")
            .into_string()
            .map_err(|_| anyhow!("ARGON2_PHC_VERSION is invalid value."))?
            .parse::<u32>()?;

        let time_cost = env::var_os("ARGON2_PHC_PARAM_TIME_COST")
            .expect("ARGON2_PHC_TIME_COST is undefined.")
            .into_string()
            .map_err(|_| anyhow!("ARGON2_PHC_PARAM_TIME_COST is invalid value."))?
            .parse::<u32>()?;

        let memory_cost = env::var_os("ARGON2_PHC_PARAM_MEMORY_COST")
            .expect("ARGON2_PHC_MEMORY_COST is undefined.")
            .into_string()
            .map_err(|_| anyhow!("ARGON2_PHC_PARAM_MEMORY_COST is invalid value."))?
            .parse::<u32>()?;

        let parallelism_cost = env::var_os("ARGON2_PHC_PARAM_PARALLELISM_COST")
            .expect("ARGON2_PHC_PARALLELISM_COST is undefined.")
            .into_string()
            .map_err(|_| anyhow!("ARGON2_PHC_PARAM_PARALLELISM_COST is invalid value."))?
            .parse::<u32>()?;

        Ok(EncryptionData::new(
            variant,
            salt,
            version,
            time_cost,
            memory_cost,
            parallelism_cost,
        ))
    }

    pub fn new(
        variant: String,
        salt: String,
        version: u32,
        time_cost: u32,
        memory_cost: u32,
        parallelism_cost: u32,
    ) -> Self {
        Self {
            variant,
            salt,
            version,
            time_cost,
            memory_cost,
            parallelism_cost,
        }
    }
}
