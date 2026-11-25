//! The protected key text, checked against the published vector and against damaged input.

use serde_json::Value;

use super::*;

const PUBLISHED: &str = include_str!("../../tests/vectors/riegel-v1.json");
const PASSPHRASE: &str = "Riegel-Prüfung 1";

fn published() -> Value {
    serde_json::from_str(PUBLISHED).unwrap()
}

fn plain_text() -> String {
    published()["secret_key"].as_str().unwrap().to_owned()
}

fn protected_text() -> String {
    published()["protected_secret_key"]["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The published protected text with one bit changed in byte `offset` of its data.
fn protected_text_with_flipped_bit(offset: usize) -> String {
    let text = protected_text();
    let mut data = Base64::decode_vec(text.strip_prefix(PROTECTED_PREFIX).unwrap()).unwrap();
    data[offset] ^= 1;
    format!("{PROTECTED_PREFIX}{}", Base64::encode_string(&data))
}

#[test]
fn protecting_with_the_published_salt_gives_the_published_text() {
    let published = published();
    let vector = &published["protected_secret_key"];
    let key: SecretKey = plain_text().parse().unwrap();
    let salt: [u8; SALT_LEN] = hex::decode(vector["salt"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let text = key
        .to_protected_text_with_salt(vector["passphrase"].as_str().unwrap(), &salt)
        .unwrap();

    assert_eq!(*text, vector["text"].as_str().unwrap());
}

#[test]
fn published_protected_key_opens_with_its_passphrase() {
    let key = SecretKey::from_protected_text(&protected_text(), PASSPHRASE).unwrap();

    assert_eq!(*key.to_text(), plain_text());
}

#[test]
fn protected_text_may_be_surrounded_by_whitespace() {
    let text = format!("  {}\r\n", protected_text());

    let key = SecretKey::from_protected_text(&text, PASSPHRASE).unwrap();

    assert_eq!(*key.to_text(), plain_text());
}

#[test]
fn protecting_the_same_key_twice_gives_different_texts() {
    let key: SecretKey = plain_text().parse().unwrap();

    let first = key.to_protected_text(PASSPHRASE).unwrap();
    let second = key.to_protected_text(PASSPHRASE).unwrap();

    assert_ne!(*first, *second);
}

#[test]
fn rejects_the_wrong_passphrase() {
    assert!(matches!(
        SecretKey::from_protected_text(&protected_text(), "Riegel-Prüfung 2"),
        Err(Error::WrongPassphrase)
    ));
}

#[test]
fn rejects_an_empty_passphrase_when_protecting() {
    let key: SecretKey = plain_text().parse().unwrap();

    assert!(matches!(
        key.to_protected_text(""),
        Err(Error::InvalidPassphrase(_))
    ));
}

#[test]
fn rejects_an_empty_passphrase_when_opening() {
    assert!(matches!(
        SecretKey::from_protected_text(&protected_text(), ""),
        Err(Error::InvalidPassphrase(_))
    ));
}

#[test]
fn rejects_modified_salt() {
    let text = protected_text_with_flipped_bit(0);

    assert!(matches!(
        SecretKey::from_protected_text(&text, PASSPHRASE),
        Err(Error::WrongPassphrase)
    ));
}

#[test]
fn rejects_modified_encrypted_seed() {
    let text = protected_text_with_flipped_bit(SALT_LEN);

    assert!(matches!(
        SecretKey::from_protected_text(&text, PASSPHRASE),
        Err(Error::WrongPassphrase)
    ));
}

#[test]
fn rejects_modified_tag() {
    let text = protected_text_with_flipped_bit(PROTECTED_LEN - 1);

    assert!(matches!(
        SecretKey::from_protected_text(&text, PASSPHRASE),
        Err(Error::WrongPassphrase)
    ));
}

#[test]
fn rejects_protected_text_that_is_too_short() {
    let one_byte_short = Base64::encode_string(&[0; PROTECTED_LEN - 1]);

    assert!(matches!(
        SecretKey::from_protected_text(&format!("{PROTECTED_PREFIX}{one_byte_short}"), PASSPHRASE),
        Err(Error::InvalidKey(_))
    ));
}

#[test]
fn plain_secret_key_is_not_accepted_as_protected_key() {
    assert!(matches!(
        SecretKey::from_protected_text(&plain_text(), PASSPHRASE),
        Err(Error::InvalidKey(_))
    ));
}
