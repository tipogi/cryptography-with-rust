use std::path::Path;

use identity::elements::private_identity::PrivateIdentity;
use identity::utils::environment::Environment;

const BINARY_MSG: &[u8; 47] = b"walk a bit in the sand before shower in the sea";
const MSG_SIGNATURE: &str = "B118C41734FAA0B1BB8CFF90DF12D1CF4E74592F1FE6B3A3A3FE5E5F219909DEF116172BE5A71BDDF9B8A90CD8063732206E2150572792E9478B1F484E031700";
const BASE64_URL_IDENTITY: &str = "ASzMbRn6q8rLfJgFBOVx4ruuUG4arE6flhsO-_TKXG2B1bYr2kVKkKHwCO2Ly0-5mOwAb-O0RPi21EU0gYrKtAfnP0y9iS-U7WYwiKEFpHuFS_yMO2hgw1Bj36CEa6FDeg";
const PEM_PATH: &str = "./files/key.pem";

fn create_identity() -> PrivateIdentity {
    let env = Environment::init().unwrap();

    let username = &env.username;
    let password = &env.password;

    PrivateIdentity::new(username, password).unwrap()
}

fn create_pem_file() {
    let identity = create_identity();
    match Path::new(PEM_PATH).exists() {
        false => identity.create_pem_file(PEM_PATH, false),
        true => ()
    }
}

#[test]
fn sign_message_from_identity() {
    let mut identity = create_identity();
    let signature = identity.sign(BINARY_MSG);

    assert_eq!(
        signature.to_string(), 
        MSG_SIGNATURE
    );
}

#[test]
fn parse_to_base64_url() {
    let identity = create_identity();
    let private_identity_base64url = identity.to_base64_url().unwrap();
    
    assert_eq!(
        private_identity_base64url,
        BASE64_URL_IDENTITY
    )
}

#[test]
fn create_identity_from_base64_url() {
    let mut identity = PrivateIdentity::from_base64_url(BASE64_URL_IDENTITY.to_string()).unwrap();
    let signature = identity.sign(BINARY_MSG);

    assert_eq!(
        signature.to_string(), 
        MSG_SIGNATURE
    );
}


#[test]
fn sign_message_from_pem_file() {
    create_pem_file();
    let signature = PrivateIdentity::sign_message_from_pem_file(PEM_PATH, BINARY_MSG);

    assert_eq!(
        signature.to_string(), 
        MSG_SIGNATURE
    );
}