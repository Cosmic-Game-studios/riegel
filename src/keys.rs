//! Key pairs and their text encoding (SPEC.md, section 3).

use std::fmt::{self, Write};
use std::str::FromStr;

use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};
use x_wing::{
    DECAPSULATION_KEY_SIZE, DecapsulationKeyRejectNonContrib, Decapsulator, ENCAPSULATION_KEY_SIZE,
    EncapsulationKey, KeyExport, KeyInit,
};
use zeroize::Zeroizing;

use crate::Error;
use crate::passphrase::PROTECTED_PREFIX;

const PUBLIC_PREFIX: &str = "riegel-pub-1:";
const SECRET_PREFIX: &str = "riegel-sec-1:";

/// A recipient's public key. Anyone who has it can encrypt to the holder of the matching
/// [`SecretKey`]; it does not need to be kept secret, but it must reach the sender unmodified.
///
/// Its text form (`Display`, `FromStr`) is `riegel-pub-1:` followed by Base64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub(crate) EncapsulationKey);

/// A secret key. Whoever holds it can decrypt everything ever encrypted to its [`PublicKey`].
///
/// It has two text forms. The protected one (`to_protected_text`, `from_protected_text`) is
/// encrypted under a passphrase and is the one to store. The plain one (`to_text`, `FromStr`)
/// is `riegel-sec-1:` followed by Base64 and gives the key to anyone who can read it. There
/// is intentionally no `Display`, so the key cannot end up in a log line by accident.
#[derive(Clone)]
pub struct SecretKey(pub(crate) DecapsulationKeyRejectNonContrib);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey").finish_non_exhaustive()
    }
}

impl SecretKey {
    /// Generates a new key from the operating system's random number generator.
    ///
    /// # Errors
    /// [`Error::Rng`] if the operating system cannot supply random bytes.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0u8; DECAPSULATION_KEY_SIZE]);
        getrandom::fill(seed.as_mut_slice())?;
        Ok(Self::from_seed(&seed))
    }

    /// The public key that encrypts to this secret key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.encapsulation_key().clone())
    }

    /// The key in its plain, unencrypted text form. The returned string is wiped from memory
    /// when dropped.
    #[must_use]
    pub fn to_text(&self) -> Zeroizing<String> {
        let encoded = Zeroizing::new(Base64::encode_string(self.seed().as_slice()));
        let mut text = Zeroizing::new(String::with_capacity(SECRET_PREFIX.len() + encoded.len()));
        text.push_str(SECRET_PREFIX);
        text.push_str(&encoded);
        text
    }

    /// The 32 random bytes the whole key pair is derived from.
    pub(crate) fn seed(&self) -> Zeroizing<[u8; DECAPSULATION_KEY_SIZE]> {
        Zeroizing::new(self.0.to_bytes().into())
    }

    pub(crate) fn from_seed(seed: &[u8; DECAPSULATION_KEY_SIZE]) -> Self {
        Self(DecapsulationKeyRejectNonContrib::new(seed.into()))
    }
}

impl FromStr for SecretKey {
    type Err = Error;

    /// Parses the plain text form. Surrounding whitespace is ignored, so the contents of a key
    /// file can be passed as read.
    ///
    /// # Errors
    /// [`Error::PassphraseRequired`] if the text is a passphrase-protected key, which
    /// [`SecretKey::from_protected_text`] reads; [`Error::InvalidKey`] if it is no secret key.
    fn from_str(text: &str) -> Result<Self, Error> {
        let text = text.trim();
        if text.starts_with(PROTECTED_PREFIX) {
            return Err(Error::PassphraseRequired);
        }
        let encoded = text.strip_prefix(SECRET_PREFIX).ok_or(Error::InvalidKey(
            "not a secret key: it must start with \"riegel-sec-1:\"",
        ))?;
        let seed: Zeroizing<[u8; DECAPSULATION_KEY_SIZE]> = decode_exact(encoded)?;
        Ok(Self::from_seed(&seed))
    }
}

impl PublicKey {
    /// A digest of the key for comparing two copies of it by eye or over the phone: the
    /// SHA-256 of the key in hexadecimal, in sixteen groups of four characters.
    ///
    /// A sender who has checked the fingerprint with the recipient over a channel they trust
    /// knows that the public key was not replaced on the way.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0.to_bytes());
        let mut text = String::with_capacity(16 * 5);
        let (groups, _) = digest.as_chunks::<2>();
        for (index, [high, low]) in groups.iter().enumerate() {
            if index > 0 {
                text.push(' ');
            }
            write!(text, "{high:02x}{low:02x}").expect("writing to a String cannot fail");
        }
        text
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PUBLIC_PREFIX)?;
        f.write_str(&Base64::encode_string(self.0.to_bytes().as_slice()))
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    /// Surrounding whitespace is ignored, so the contents of a key file can be passed as read.
    fn from_str(text: &str) -> Result<Self, Error> {
        let encoded = text
            .trim()
            .strip_prefix(PUBLIC_PREFIX)
            .ok_or(Error::InvalidKey(
                "not a public key: it must start with \"riegel-pub-1:\"",
            ))?;
        let bytes: Zeroizing<[u8; ENCAPSULATION_KEY_SIZE]> = decode_exact(encoded)?;
        // Fails when the ML-KEM part is not a canonically encoded key (FIPS 203, section 7.2).
        EncapsulationKey::try_from(bytes.as_slice())
            .map(Self)
            .map_err(|_| Error::InvalidKey("the key data is not a valid X-Wing public key"))
    }
}

/// Decodes Base64 that must hold exactly `N` bytes.
pub(crate) fn decode_exact<const N: usize>(encoded: &str) -> Result<Zeroizing<[u8; N]>, Error> {
    const MALFORMED: Error = Error::InvalidKey("the key data is damaged or has the wrong length");

    let mut bytes = Zeroizing::new([0u8; N]);
    let decoded_len = Base64::decode(encoded, bytes.as_mut_slice())
        .map_err(|_| MALFORMED)?
        .len();
    if decoded_len != N {
        return Err(MALFORMED);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_TEXT: &str = "riegel-sec-1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    fn public_text() -> String {
        SECRET_TEXT
            .parse::<SecretKey>()
            .unwrap()
            .public_key()
            .to_string()
    }

    #[test]
    fn secret_key_text_round_trips() {
        let key: SecretKey = SECRET_TEXT.parse().unwrap();

        assert_eq!(*key.to_text(), SECRET_TEXT);
    }

    #[test]
    fn public_key_text_round_trips() {
        let text = public_text();

        let key: PublicKey = text.parse().unwrap();

        assert!(text.starts_with("riegel-pub-1:"));
        assert_eq!(key.to_string(), text);
    }

    #[test]
    fn key_text_may_be_surrounded_by_whitespace() {
        let key: SecretKey = format!("  {SECRET_TEXT}\r\n").parse().unwrap();

        assert_eq!(*key.to_text(), SECRET_TEXT);
    }

    #[test]
    fn generated_keys_differ() {
        let first = SecretKey::generate().unwrap();
        let second = SecretKey::generate().unwrap();

        assert_ne!(*first.to_text(), *second.to_text());
    }

    #[test]
    fn fingerprint_is_the_grouped_sha256_of_the_key() {
        let key: PublicKey = public_text().parse().unwrap();

        assert_eq!(
            key.fingerprint(),
            "c9a3 565f fde4 f72b 5166 1be3 91ee 13e4 6378 d7f0 6dd5 c8bf 5af9 d2cf b5b8 336b"
        );
    }

    #[test]
    fn protected_secret_key_asks_for_its_passphrase() {
        let protected = "riegel-sec-pw-1:EBESExQVFhcYGRobHB0eH3Sey3GcT+jFYyfNlEX2E0wlAP73VqC5                         KeARM/MApwsnwQ71Hxu9cZK4EI07gXU2Xg==";

        assert!(matches!(
            protected.parse::<SecretKey>(),
            Err(Error::PassphraseRequired)
        ));
    }

    #[test]
    fn public_key_is_not_accepted_as_secret_key() {
        assert!(matches!(
            public_text().parse::<SecretKey>(),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn secret_key_is_not_accepted_as_public_key() {
        assert!(matches!(
            SECRET_TEXT.parse::<PublicKey>(),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn rejects_secret_key_that_is_too_short() {
        let thirty_one_bytes = Base64::encode_string(&[0; DECAPSULATION_KEY_SIZE - 1]);

        assert!(matches!(
            format!("riegel-sec-1:{thirty_one_bytes}").parse::<SecretKey>(),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn rejects_secret_key_that_is_too_long() {
        let thirty_three_bytes = Base64::encode_string(&[0; DECAPSULATION_KEY_SIZE + 1]);

        assert!(matches!(
            format!("riegel-sec-1:{thirty_three_bytes}").parse::<SecretKey>(),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn rejects_key_that_is_not_base64() {
        assert!(matches!(
            "riegel-sec-1:not base64 at all!".parse::<SecretKey>(),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn rejects_public_key_with_out_of_range_ml_kem_coefficients() {
        // All bits set encodes coefficients of 4095, above the ML-KEM modulus 3329.
        let all_bits_set = Base64::encode_string(&[0xFF; ENCAPSULATION_KEY_SIZE]);

        assert!(matches!(
            format!("riegel-pub-1:{all_bits_set}").parse::<PublicKey>(),
            Err(Error::InvalidKey(_))
        ));
    }
}
