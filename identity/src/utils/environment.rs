use std::env;
use anyhow::anyhow;

#[derive(Debug)]
pub struct Environment {
    pub username: String,
    pub password: String
}

const PATH: &str = ".env";

impl Environment {
    pub fn init() -> anyhow::Result<Environment> {

        dotenv::from_path(PATH).ok();

        let username: String = env::var_os("IDENTITY_USERNAME")
            .expect("IDENTITY_USERNAME is undefined")
            .into_string()
            .map_err(|_| anyhow!("IDENTITY_USERNAME is invalid value."))?;

        let password = env::var_os("IDENTITY_PASSWORD")
            .expect("IDENTITY_PASSWORD is undefined.")
            .into_string()
            .map_err(|_| anyhow!("IDENTITY_PASSWORD is invalid value."))?;

        Ok(Environment::new(
            username,
            password
        ))
    }

    pub fn new(
        username: String,
        password: String,
    ) -> Self {
        Self {
            username,
            password
        }
    }
}
