use std::array::TryFromSliceError;
use anyhow::anyhow;
use ed25519_dalek::{ed25519::signature::SignerMut, Signature, SigningKey, Verifier};
use ed25519_dalek::pkcs8::{ EncodePrivateKey, DecodePrivateKey };
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use crate::utils::{error::Error, hasher::hash_input};
use super::version::Version;

// An identity that includes public and private key components.
// This can be used to both sign and verify.
pub struct PrivateIdentity {
    // The algorithm version for this Identity
    pub version: Version,

    // The public identity derived from the username. This can be freely distributed ✓
	// Format: base64_url
    pub public_id: String,

    // The public and private keys for this Identity. This should **not** be shared 𐄂
	// ed25519 signing key which can be used to produce signatures
    pub keypair: SigningKey,
}

impl PrivateIdentity {
    pub fn new(username: &String, password: &String) -> anyhow::Result<PrivateIdentity> {

        let username_hash = hash_input(username).map_err(|e| anyhow!(e))?;
		println!("Username hash: {:}", username_hash.len());

        let public_id = base64_url::encode(&username_hash);
		println!("public id hash base64_URL: {:}", public_id);

        let credentials = format!("{}{}", username, password);
        let hashed_credentials = hash_input(&credentials)
			.map_err(|e| anyhow!(e))?;

		// TODO: The length of the byte array now is 32 bytes. We have the default value of the hash
		// which is 32 bytes
        let secret_32: [u8; 32] = hashed_credentials.as_bytes()[..32]
            .try_into()
            .map_err(|e: TryFromSliceError| anyhow!(e))?;

        // Other way to split an array
        // let mut example: [u8; 32] = [0; 32];
        // example.copy_from_slice(&hashed_credentials.as_bytes()[..32]);

        let keypair = SigningKey::from_bytes(&secret_32);

        let identity = PrivateIdentity {
			public_id,
			keypair,
			version: Version::V1
		};

		Ok(identity)
    }

	pub fn sign(&mut self, message: &[u8]) -> Signature {
		self.keypair.sign(message)
	}

	pub fn verify(&self, signature: &Signature, message: &[u8]) -> anyhow::Result<bool>{
		self.keypair.verify(message, signature)
			.map_err(|e| anyhow!(e.to_string()))?;
		println!("Signature verification succesful!");
		Ok(true)
	}

	pub fn verify_from_public_key(&self, signature: &Signature, message: &[u8]) -> anyhow::Result<bool>{
		let public_key = self.keypair.verifying_key();
		public_key.verify(message, signature)
			.map_err(|e| anyhow!(e))?;
		println!("Verified the authenticity of the signature with the public key!");
		Ok(true)
	}

	pub fn to_base64_url(&self) -> anyhow::Result<String, Error> {
		let public_id_binary = match base64_url::decode(&self.public_id) {
			Ok(binary) => binary,
			Err(_) => return Err(Error::InvalidBase64String)
		};

		let binary_vector: Vec<u8> = [
			&[self.version.to_u8()], // 1 byte
			&public_id_binary as &[u8], // 32 byte
			// The first SECRET_KEY_LENGTH(32) of bytes is the SecretKey, and the next PUBLIC_KEY_LENGTH(32) bytes is the VerifyingKey
			&self.keypair.to_keypair_bytes() // 64 byte
		].concat();

		Ok(base64_url::encode(&binary_vector))
	}

	pub fn from_base64_url(private_identity: String) -> anyhow::Result<PrivateIdentity, Error> {
		let binary = match base64_url::decode(&private_identity) {
			Ok(private) => private,
			Err(_)	=> return Err(Error::InvalidBase64String)
		};

		if binary.is_empty() { return Err(Error::EmptyString) }

		let version = Version::from_u8(&binary[0]);

		match version {
			Version::V1 => {
				if binary.len() != 97 { return Err(Error::InvalidPrivateIdentity)}
				let public_id = base64_url::encode(&binary[1..33]);

				let binary_keypair: &[u8; 64] = &binary[33..97]
					.try_into()
					.unwrap();
				let keypair = match SigningKey::from_keypair_bytes(binary_keypair) {
					Ok(keys) => keys,
					Err(_) => return Err(Error::InvalidPrivateKey)
				};
				Ok(PrivateIdentity {
					version,
					public_id,
					keypair
				})
			},
			Version::Unknown => return Err(Error::InvalidUnknownVersion)
		}
	}

	pub fn create_pem_file(&self, path: &str, zeroize_output: bool) {
		// IMPORTANT to set a label for the pem, if not we are not going to be able to
		// decode to signing key
		let label: & 'static str = "PRIVATE KEY";
		let secret_document = self.keypair.to_pkcs8_der().unwrap();

		let pem = secret_document.to_pem(label, LineEnding::default()).unwrap();

		if zeroize_output { println!("PEM: {:?}", pem); 
	}
		secret_document.write_pem_file(path, label, LineEnding::default()).unwrap();
	}

	pub fn sign_message_from_pem_file(path: &str, message: &[u8]) -> Signature {
		let mut signing_key: SigningKey = DecodePrivateKey::read_pkcs8_pem_file(path).unwrap();
		signing_key.sign(message)
	}
}
