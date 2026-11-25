//! Riegel: hybrid post-quantum public-key encryption for files and byte streams.
//!
//! A message is encrypted to a recipient's [`PublicKey`] and can only be read with the matching
//! [`SecretKey`]. The key exchange is X-Wing (ML-KEM-768 combined with X25519), so the message
//! stays confidential as long as *either* of the two holds. `SPEC.md` in the repository is the
//! normative description of the format.
//!
//! Riegel provides confidentiality and integrity only. It does not authenticate the sender and
//! it has no forward secrecy; see `SECURITY.md` before relying on it.
//!
//! ```
//! # fn main() -> Result<(), riegel::Error> {
//! let secret = riegel::SecretKey::generate()?;
//! let recipient = secret.public_key();
//!
//! let mut sealed = Vec::new();
//! riegel::encrypt(&recipient, &b"attack at dawn"[..], &mut sealed)?;
//!
//! let mut opened = Vec::new();
//! riegel::decrypt(&secret, &sealed[..], &mut opened)?;
//! assert_eq!(opened, b"attack at dawn");
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod container;
mod error;
mod keys;
mod passphrase;

pub use container::{decrypt, encrypt};
pub use error::Error;
pub use keys::{PublicKey, SecretKey};
