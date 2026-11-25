use std::fmt;
use std::io;

/// Why a Riegel operation failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Reading the input or writing the output failed.
    Io(io::Error),
    /// The operating system could not supply random bytes.
    Rng(getrandom::Error),
    /// The text is not a valid key of the expected kind; the message says what is wrong.
    InvalidKey(&'static str),
    /// The secret key is passphrase-protected and has to be read with
    /// [`SecretKey::from_protected_text`](crate::SecretKey::from_protected_text).
    PassphraseRequired,
    /// The passphrase cannot be used; the message says why.
    InvalidPassphrase(&'static str),
    /// The protected secret key could not be decrypted: the passphrase is wrong, or the key
    /// text was damaged or modified. The cases cannot be told apart.
    WrongPassphrase,
    /// The memory needed to derive a key from a passphrase (64 MiB) could not be allocated.
    OutOfMemory,
    /// The input does not start with the Riegel magic bytes.
    NotRiegel,
    /// The input is a Riegel container in a format version this library does not implement.
    UnsupportedVersion(u8),
    /// The container could not be decrypted: the key is wrong, or the data was truncated,
    /// corrupted or tampered with. The cases are deliberately not told apart.
    DecryptionFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Rng(error) => write!(f, "system random number generator failed: {error}"),
            Self::InvalidKey(reason) => write!(f, "invalid key: {reason}"),
            Self::PassphraseRequired => f.write_str("the secret key is passphrase-protected"),
            Self::InvalidPassphrase(reason) => write!(f, "invalid passphrase: {reason}"),
            Self::WrongPassphrase => {
                f.write_str("wrong passphrase, or the secret key file is damaged")
            }
            Self::OutOfMemory => {
                f.write_str("not enough memory to process the passphrase (64 MiB are needed)")
            }
            Self::NotRiegel => f.write_str("not a Riegel file"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported Riegel format version {version}")
            }
            Self::DecryptionFailed => {
                f.write_str("decryption failed: wrong key, or the file is damaged or was modified")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Rng(error) => Some(error),
            Self::InvalidKey(_)
            | Self::PassphraseRequired
            | Self::InvalidPassphrase(_)
            | Self::WrongPassphrase
            | Self::OutOfMemory
            | Self::NotRiegel
            | Self::UnsupportedVersion(_)
            | Self::DecryptionFailed => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<getrandom::Error> for Error {
    fn from(error: getrandom::Error) -> Self {
        Self::Rng(error)
    }
}
