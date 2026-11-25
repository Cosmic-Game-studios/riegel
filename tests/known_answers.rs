//! The cryptographic building blocks, checked against the test vectors of their own
//! specifications. A failure here means a dependency no longer computes what its standard
//! says, whatever the Riegel-level tests report.

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use x_wing::{DecapsulationKeyRejectNonContrib, Decapsulator, KeyExport, TryDecapsulate};

/// The vectors of draft-connolly-cfrg-xwing-kem (`spec/test-vectors.json`).
const X_WING_VECTORS: &str = include_str!("vectors/x-wing-draft.json");

#[test]
fn x_wing_matches_the_draft_test_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(X_WING_VECTORS).unwrap();
    let vectors = vectors.as_array().unwrap();
    assert_eq!(vectors.len(), 3);

    for vector in vectors {
        let field = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
        let seed: [u8; 32] = field("seed").try_into().unwrap();
        let encapsulation_seed: [u8; 64] = field("eseed").try_into().unwrap();

        let key = DecapsulationKeyRejectNonContrib::from(seed);
        let (ciphertext, shared_secret) = key
            .encapsulation_key()
            .encapsulate_deterministic(&encapsulation_seed.into());

        assert_eq!(key.encapsulation_key().to_bytes().as_slice(), field("pk"));
        assert_eq!(ciphertext.as_slice(), field("ct"));
        assert_eq!(shared_secret.as_slice(), field("ss"));
        assert_eq!(
            key.try_decapsulate(&ciphertext).unwrap().as_slice(),
            field("ss")
        );
    }
}

#[test]
fn hkdf_sha256_matches_rfc_5869_test_case_1() {
    let input_key = [0x0b; 22];
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let mut output = [0u8; 42];

    Hkdf::<Sha256>::new(Some(&salt), &input_key)
        .expand(&info, &mut output)
        .unwrap();

    assert_eq!(
        hex::encode(output),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

/// The case without a salt, which is how Riegel calls HKDF.
#[test]
fn hkdf_sha256_matches_rfc_5869_test_case_3() {
    let input_key = [0x0b; 22];
    let mut output = [0u8; 42];

    Hkdf::<Sha256>::new(None, &input_key)
        .expand(&[], &mut output)
        .unwrap();

    assert_eq!(
        hex::encode(output),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn chacha20_poly1305_matches_rfc_8439_section_2_8_2() {
    let key: [u8; 32] =
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap()
            .try_into()
            .unwrap();
    let nonce: [u8; 12] = hex::decode("070000004041424344454647")
        .unwrap()
        .try_into()
        .unwrap();
    let associated_data = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let mut message = b"Ladies and Gentlemen of the class of '99: If I could offer you \
        only one tip for the future, sunscreen would be it."
        .to_vec();

    ChaCha20Poly1305::new(&key.into())
        .encrypt_in_place(&nonce.into(), &associated_data, &mut message)
        .unwrap();

    assert_eq!(
        hex::encode(message),
        concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691",
        )
    );
}

#[test]
fn argon2id_matches_rfc_9106_section_5_3() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04; 12]).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let mut tag = [0u8; 32];

    Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
        .unwrap()
        .hash_password_into(&[0x01; 32], &[0x02; 16], &mut tag)
        .unwrap();

    assert_eq!(
        hex::encode(tag),
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );
}
