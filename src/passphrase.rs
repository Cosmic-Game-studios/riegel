//! The passphrase-protected text form of a secret key (SPEC.md, section 3.3).

use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64, Encoding};
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce};
use x_wing::DECAPSULATION_KEY_SIZE;
use zeroize::Zeroizing;

use crate::keys::decode_exact;
use crate::{Error, SecretKey};

pub(crate) const PROTECTED_PREFIX: &str = "riegel-sec-pw-1:";
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
/// Salt, then the encrypted seed with its tag.
const PROTECTED_LEN: usize = SALT_LEN + DECAPSULATION_KEY_SIZE + TAG_LEN;

// The second recommended parameter set of RFC 9106, section 4. The values are part of the
// format: they are fixed by the key prefix and never read from the key text.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_PASSES: u32 = 3;
const ARGON2_LANES: u32 = 4;

impl SecretKey {
    /// The key in its protected text form: encrypted under a key that Argon2id derives from
    /// `passphrase`. Whoever obtains the text still has to guess the passphrase, and every
    /// guess costs them 64 MiB of memory and a noticeable amount of time.
    ///
    /// The protection is only as strong as the passphrase is hard to guess.
    ///
    /// # Errors
    /// [`Error::InvalidPassphrase`] if the passphrase is empty, [`Error::Rng`] if the
    /// operating system cannot supply random bytes, [`Error::OutOfMemory`] if the memory for
    /// Argon2id cannot be allocated.
    pub fn to_protected_text(&self, passphrase: &str) -> Result<Zeroizing<String>, Error> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt)?;
        self.to_protected_text_with_salt(passphrase, &salt)
    }

    /// The deterministic core of [`Self::to_protected_text`]. The salt must be fresh and
    /// random for every call: it is what makes each wrapping key single-use.
    fn to_protected_text_with_salt(
        &self,
        passphrase: &str,
        salt: &[u8; SALT_LEN],
    ) -> Result<Zeroizing<String>, Error> {
        let cipher = wrapping_cipher(passphrase, salt)?;
        let mut sealed_seed = Zeroizing::new(Vec::with_capacity(DECAPSULATION_KEY_SIZE + TAG_LEN));
        sealed_seed.extend_from_slice(self.seed().as_slice());
        cipher
            .encrypt_in_place(
                &wrapping_nonce(),
                PROTECTED_PREFIX.as_bytes(),
                &mut *sealed_seed,
            )
            .expect("32 bytes are far below the ChaCha20-Poly1305 message limit");

        let mut text = String::from(PROTECTED_PREFIX);
        text.push_str(&Base64::encode_string(
            &[salt.as_slice(), &sealed_seed].concat(),
        ));
        Ok(Zeroizing::new(text))
    }

    /// Reads a key from its protected text form. Surrounding whitespace is ignored, so the
    /// contents of a key file can be passed as read.
    ///
    /// # Errors
    /// [`Error::InvalidKey`] if the text is no protected secret key,
    /// [`Error::InvalidPassphrase`] if the passphrase is empty, [`Error::WrongPassphrase`] if
    /// the passphrase is wrong or the text was damaged or modified, [`Error::OutOfMemory`] if
    /// the memory for Argon2id cannot be allocated.
    pub fn from_protected_text(text: &str, passphrase: &str) -> Result<Self, Error> {
        let encoded = text
            .trim()
            .strip_prefix(PROTECTED_PREFIX)
            .ok_or(Error::InvalidKey(
                "not a passphrase-protected secret key: it must start with \"riegel-sec-pw-1:\"",
            ))?;
        let protected: Zeroizing<[u8; PROTECTED_LEN]> = decode_exact(encoded)?;
        let (salt, sealed_seed) = protected.split_at(SALT_LEN);
        let salt: &[u8; SALT_LEN] = salt.try_into().expect("split at the salt length");

        let cipher = wrapping_cipher(passphrase, salt)?;
        let mut seed = Zeroizing::new(sealed_seed.to_vec());
        cipher
            .decrypt_in_place(&wrapping_nonce(), PROTECTED_PREFIX.as_bytes(), &mut *seed)
            .map_err(|_| Error::WrongPassphrase)?;
        let seed: &[u8; DECAPSULATION_KEY_SIZE] = seed
            .as_slice()
            .try_into()
            .expect("the opened seed has the secret key length");
        Ok(Self::from_seed(seed))
    }
}

/// Derives the cipher that encrypts the seed from the passphrase and the salt.
fn wrapping_cipher(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<ChaCha20Poly1305, Error> {
    if passphrase.is_empty() {
        return Err(Error::InvalidPassphrase("it must not be empty"));
    }
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_LANES, Some(32))
        .expect("the fixed Argon2 parameters are valid");

    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .map_err(|error| match error {
            argon2::Error::OutOfMemory => Error::OutOfMemory,
            argon2::Error::PwdTooLong => Error::InvalidPassphrase("it is too long"),
            other => unreachable!("Argon2 rejected fixed-size inputs: {other}"),
        })?;
    Ok(ChaCha20Poly1305::new((&*key).into()))
}

/// The all-zero nonce. It never repeats under one key, because a wrapping key belongs to one
/// freshly drawn salt and encrypts exactly one seed.
fn wrapping_nonce() -> Nonce {
    Nonce::default()
}

#[cfg(test)]
mod tests;
