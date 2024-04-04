use anyhow::anyhow;
use ed25519_dalek::VerifyingKey;

use crate::utils::error::Error;

use super::{private_identity::PrivateIdentity, version::Version};

// Identity that includes only public components. 
// This can be used to verify, but not sign.
pub struct PublicIdentity {

	// The public identity derived from the username. This can be freely distributed ✓.
	// Format: base64_url
	pub public_id: String,

	// The public key for this PublicIdentity. This can be freely distributed ✓.
	// An ed25519 public key.
	pub public_key: VerifyingKey,

	// The algorithm version for this PublicIdentity.
	pub version: Version,
}

impl PublicIdentity {

	pub fn new(username: &String, password: &String) -> anyhow::Result<Self> {
		let private_identity = PrivateIdentity::new(username, password)?;
		Ok(Self {
			public_id: private_identity.public_id,
			public_key: private_identity.keypair.verifying_key(),
			version: private_identity.version
		})
	}

	// base64_url is more suitable for embedding in URLs. For example, JWT uses that one
	pub fn to_base64_url(self) -> anyhow::Result<String> {
		// Decode the base64url to binary array. The size is going to be decresed to 32 bytes
		// if the default length is 32 bytes
		let public_id_binary = match base64_url::decode(&self.public_id) {
			Ok(res) => res,
			Err(e) => return Err(anyhow!(e))
		};

		let merged_properties: Vec<u8> = [
			&[self.version.to_u8()], // 1 byte
			&public_id_binary as &[u8], // 32 bytes
			// defined in PUBLIC_KEY_LENGTH in ed25519_dalek crate
			self.public_key.as_bytes() // 32 bytes
		].concat();

		Ok(base64_url::encode(&merged_properties))
	}

	pub fn from_base64_url(identity: String) -> anyhow::Result<PublicIdentity, Error> {
		let identity_binary = match base64_url::decode(&identity) {
			Ok(data) => data,
			Err(_) => return Err(Error::InvalidBase64String)
		};

		if identity_binary.is_empty() { return Err(Error::EmptyString); }

		let version_u8 = identity_binary[0];
		let version = Version::from_u8(&version_u8);

		match version {
			Version::V1 => {
				if identity_binary.len() != 65 { return Err(Error::InvalidPublicIdentity)}
				let public_id = base64_url::encode(&identity_binary[1..33] );

				// Create a 32 byte array to create the verifying key
				let mut public_key_binary: [u8; 32] = [0; 32];
				public_key_binary.copy_from_slice(&identity_binary[33..65]);
				let public_key = match VerifyingKey::from_bytes(&public_key_binary) {
					Ok(key) => key,
					Err(_) => return Err(Error::InvalidPublicKey)
				};
				// Create the public identity
				return Ok(PublicIdentity {
					public_id,
					public_key,
					version
				});
			},
			Version::Unknown => return Err(Error::InvalidUnknownVersion)
		}
	}
}