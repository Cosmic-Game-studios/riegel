//! The container format, checked against the published vectors and against damaged input.

use ml_kem::ml_kem_768;
use serde_json::Value;
use sha3::Sha3_256;

use super::*;

const PUBLISHED: &str = include_str!("../../tests/vectors/riegel-v1.json");
const ML_KEM_PUBLIC_KEY_LEN: usize = 1184;
const ML_KEM_CIPHERTEXT_LEN: usize = 1088;
/// Offset of the X25519 share, the last 32 bytes of the header.
const X25519_SHARE_START: usize = PREAMBLE_LEN + ML_KEM_CIPHERTEXT_LEN;
/// Offset of the first sealed chunk.
const PAYLOAD_START: usize = HEADER_LEN + COMMITMENT_LEN;
/// A sealed full chunk.
const SEALED_CHUNK_LEN: usize = CHUNK_LEN + TAG_LEN;
const RANDOMNESS: [u8; ENCAPSULATION_RANDOMNESS_SIZE] = [7; ENCAPSULATION_RANDOMNESS_SIZE];

fn published() -> Value {
    serde_json::from_str(PUBLISHED).unwrap()
}

fn test_key() -> SecretKey {
    published()["secret_key"].as_str().unwrap().parse().unwrap()
}

fn other_key() -> SecretKey {
    format!("riegel-sec-1:{}8=", "/".repeat(42))
        .parse()
        .unwrap()
}

/// The plaintext rule of the published vectors.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A container holding `pattern(len)` for the test key.
fn sealed(len: usize) -> Vec<u8> {
    let mut container = Vec::new();
    encrypt_with_randomness(
        &test_key().public_key(),
        &RANDOMNESS,
        &pattern(len)[..],
        &mut container,
    )
    .unwrap();
    container
}

fn open(key: &SecretKey, container: &[u8]) -> Result<Vec<u8>, Error> {
    let mut message = Vec::new();
    decrypt(key, container, &mut message)?;
    Ok(message)
}

#[test]
fn published_vectors_encrypt_and_decrypt_as_recorded() {
    let published = published();
    let key = test_key();
    assert_eq!(
        key.public_key().to_string(),
        published["public_key"].as_str().unwrap()
    );

    for vector in published["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let plaintext = pattern(vector["plaintext_len"].as_u64().unwrap() as usize);
        let randomness: [u8; ENCAPSULATION_RANDOMNESS_SIZE] =
            hex::decode(vector["encapsulation_randomness"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();

        let mut container = Vec::new();
        encrypt_with_randomness(
            &key.public_key(),
            &randomness,
            &plaintext[..],
            &mut container,
        )
        .unwrap();

        assert_eq!(
            container.len() as u64,
            vector["ciphertext_len"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&container)),
            vector["ciphertext_sha256"].as_str().unwrap(),
            "{name}"
        );
        if let Some(ciphertext) = vector["ciphertext"].as_str() {
            assert_eq!(hex::encode(&container), ciphertext, "{name}");
        }
        assert_eq!(open(&key, &container).unwrap(), plaintext, "{name}");
    }
}

#[test]
fn encrypting_the_same_message_twice_gives_different_containers() {
    let recipient = test_key().public_key();
    let mut first = Vec::new();
    let mut second = Vec::new();

    encrypt(&recipient, &b"same message"[..], &mut first).unwrap();
    encrypt(&recipient, &b"same message"[..], &mut second).unwrap();

    assert_ne!(first, second);
}

/// Whatever single bit of a container is changed, in whichever field, it is rejected.
#[test]
fn rejects_every_single_bit_flip() {
    let key = test_key();
    let container = sealed(13);

    for offset in 0..container.len() {
        for bit in 0..8 {
            let mut damaged = container.clone();
            damaged[offset] ^= 1 << bit;

            let result = open(&key, &damaged);

            let rejected_as_expected = if offset < MAGIC.len() {
                matches!(result, Err(Error::NotRiegel))
            } else if offset == MAGIC.len() {
                matches!(result, Err(Error::UnsupportedVersion(_)))
            } else {
                matches!(result, Err(Error::DecryptionFailed))
            };
            assert!(
                rejected_as_expected,
                "bit {bit} of byte {offset}: {result:?}"
            );
        }
    }
}

/// A container cut off anywhere is rejected.
#[test]
fn rejects_every_truncation() {
    let key = test_key();
    let container = sealed(13);

    for len in 0..container.len() {
        let result = open(&key, &container[..len]);

        let rejected_as_expected = if len < PREAMBLE_LEN {
            matches!(result, Err(Error::NotRiegel))
        } else {
            matches!(result, Err(Error::DecryptionFailed))
        };
        assert!(rejected_as_expected, "first {len} bytes: {result:?}");
    }
}

#[test]
fn reports_the_version_of_a_newer_format() {
    let mut container = sealed(13);
    container[MAGIC.len()] = 2;

    assert!(matches!(
        open(&test_key(), &container),
        Err(Error::UnsupportedVersion(2))
    ));
}

#[test]
fn rejects_the_wrong_key() {
    assert!(matches!(
        open(&other_key(), &sealed(13)),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn rejects_modified_key_commitment() {
    // Nothing else depends on the commitment bytes, so only the comparison catches this.
    let mut container = sealed(13);
    container[HEADER_LEN] ^= 1;

    assert!(matches!(
        open(&test_key(), &container),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn rejects_container_missing_its_last_chunk() {
    // Cut exactly at a chunk boundary, so every remaining chunk is intact and authentic.
    let container = &sealed(CHUNK_LEN + 1)[..PAYLOAD_START + SEALED_CHUNK_LEN];

    assert!(matches!(
        open(&test_key(), container),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn rejects_data_appended_after_the_last_chunk() {
    let mut container = sealed(CHUNK_LEN);
    container.push(0);

    assert!(matches!(
        open(&test_key(), &container),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn rejects_chunks_in_the_wrong_order() {
    let mut container = sealed(2 * CHUNK_LEN + 1);
    let (first, second) = container[PAYLOAD_START..].split_at_mut(SEALED_CHUNK_LEN);
    first.swap_with_slice(&mut second[..SEALED_CHUNK_LEN]);

    assert!(matches!(
        open(&test_key(), &container),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn rejects_empty_last_chunk_after_a_full_chunk() {
    // The message of `sealed(CHUNK_LEN)`, split as a full chunk followed by an empty last
    // chunk. Both chunks are authentic, so only the rule against this encoding rejects it.
    let key = test_key();
    let header: [u8; HEADER_LEN] = sealed(CHUNK_LEN)[..HEADER_LEN].try_into().unwrap();
    let (_, shared_secret) = key
        .public_key()
        .0
        .encapsulate_deterministic(&RANDOMNESS.into());
    let (cipher, commitment) = payload_keys(&shared_secret, &header, &key.public_key().0);

    let mut full_chunk = pattern(CHUNK_LEN);
    cipher
        .encrypt_in_place(&chunk_nonce(0, false), b"", &mut full_chunk)
        .unwrap();
    let mut empty_chunk = Vec::new();
    cipher
        .encrypt_in_place(&chunk_nonce(1, true), b"", &mut empty_chunk)
        .unwrap();
    let container = [&header[..], &commitment, &full_chunk, &empty_chunk].concat();

    assert!(matches!(
        open(&key, &container),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn rejects_all_zero_x25519_shared_secret() {
    // An X25519 share of zero makes the X25519 shared secret zero for every recipient. This
    // container is otherwise consistent: its payload key and commitment are derived exactly
    // as X-Wing derives them from that zero secret, so only the explicit check rejects it.
    let key = test_key();
    let public_key = key.public_key().0.to_bytes();
    let (ml_kem_public_key, x25519_public_key) = public_key.split_at(ML_KEM_PUBLIC_KEY_LEN);
    let zero_share = [0u8; 32];
    let zero_secret = [0u8; 32];

    let ml_kem_key =
        ml_kem_768::EncapsulationKey::new(ml_kem_public_key.try_into().unwrap()).unwrap();
    let (ml_kem_ciphertext, ml_kem_secret) = ml_kem_key.encapsulate_deterministic(&[9; 32].into());
    let shared_secret = Sha3_256::new()
        .chain_update(ml_kem_secret)
        .chain_update(zero_secret)
        .chain_update(zero_share)
        .chain_update(x25519_public_key)
        .chain_update(br"\.//^\")
        .finalize();

    let mut header = [0u8; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[MAGIC.len()] = VERSION;
    header[PREAMBLE_LEN..X25519_SHARE_START].copy_from_slice(&ml_kem_ciphertext);
    header[X25519_SHARE_START..].copy_from_slice(&zero_share);
    let (cipher, commitment) = payload_keys(&shared_secret, &header, &key.public_key().0);
    let mut chunk = b"message".to_vec();
    cipher
        .encrypt_in_place(&chunk_nonce(0, true), b"", &mut chunk)
        .unwrap();
    let container = [&header[..], &commitment, &chunk].concat();

    assert!(matches!(
        open(&key, &container),
        Err(Error::DecryptionFailed)
    ));
}
