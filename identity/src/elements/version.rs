// The version of the derivation algorithm that turns credentials into keys.
#[derive(Copy, Clone, PartialEq)]
pub enum Version {
	// The first version of the derivation algorithm.
	/// EdDSA + Argon2di.
	V1 = 1,

	// Catch-all version.
	Unknown,
}

impl Version {
	// Converts the Version to a u8.
	pub fn to_u8(&self) -> u8 {
		match self {
			Version::V1 => 1u8,
			Version::Unknown => 0u8,
		}
	}

	// Converts a u8 to a Version.
	pub fn from_u8(version: &u8) -> Version {
		match version {
			1 => Version::V1,
			_ => Version::Unknown,
		}
	}
}