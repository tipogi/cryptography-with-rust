use identity::{elements::public_identity::PublicIdentity, utils::{environment::Environment, hasher::hash_input}};

const BASE64_URL_IDENTITY: &str = "ASzMbRn6q8rLfJgFBOVx4ruuUG4arE6flhsO-_TKXG2B5z9MvYkvlO1mMIihBaR7hUv8jDtoYMNQY9-ghGuhQ3o";
const PUBLIC_ID: &str = "LMxtGfqryst8mAUE5XHiu65QbhqsTp-WGw779MpcbYE";
const USERNAME: &str = "rustykey";

fn create_public_identity() -> PublicIdentity{
    let env = Environment::init().unwrap();

    let username = &env.username;
    let password = &env.password;
    
    PublicIdentity::new(username, password).unwrap()
}

#[test]
fn base64_url_public_identity() {
    let public_identity = create_public_identity();
    let base64_url = public_identity.to_base64_url().unwrap();
    
    assert_eq!(
        base64_url,
        BASE64_URL_IDENTITY
    );
}

#[test]
fn get_credentials_from_base64_url() {
    let public_itendity = PublicIdentity::from_base64_url(BASE64_URL_IDENTITY.to_string()).unwrap();
    let public_id = public_itendity.public_id;

    assert_eq!(
        PUBLIC_ID,
        public_id
    );
}

#[test]
fn generate_public_id_from_username() {
    let username_hash = hash_input(&String::from(USERNAME)).unwrap();
    let public_id = base64_url::encode(&username_hash);

    assert_eq!(
        public_id,
        PUBLIC_ID
    );
}
