use anyhow::anyhow;
use argon2::{Params, Version, Algorithm};

// Careful, if you have an identity and you change the salt you are not going to be able to reproduce
// that identity
pub const ARGON2_SALT: &str = "4PUTzg5MuaK7gGlG0rWotXWKxtYmUaKV4lNfY6joq3QVxO8";
pub const ARGON_VERSION: Version = Version::V0x13;
pub const ARGON_ALGORITHM: Algorithm = Algorithm::Argon2id;

pub fn params_v1() -> anyhow::Result<Params> {
    Params::new(
        4096,
        10,
        1,
        None).map_err(|e| anyhow!(e)
    )
}
