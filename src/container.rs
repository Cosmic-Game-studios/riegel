//! The Riegel v1 container: header, payload key derivation and the chunked AEAD payload.
//!
//! SPEC.md (sections 4 to 7) is the normative description; the constants here mirror it.

use std::io::{self, Read, Write};
use std::mem;

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x_wing::{
    CIPHERTEXT_SIZE, Ciphertext, Decapsulator, ENCAPSULATION_RANDOMNESS_SIZE, EncapsulationKey,
    KeyExport, TryDecapsulate,
};
use zeroize::Zeroizing;

use crate::{Error, PublicKey, SecretKey};

const MAGIC: &[u8; 6] = b"RIEGEL";
const VERSION: u8 = 1;
/// Magic and version: the part of the header that identifies the format.
const PREAMBLE_LEN: usize = MAGIC.len() + 1;
const HEADER_LEN: usize = PREAMBLE_LEN + CIPHERTEXT_SIZE;
const COMMITMENT_LEN: usize = 32;
const KEY_LABEL: &[u8] = b"riegel v1 payload key";
const COMMITMENT_LABEL: &[u8] = b"riegel v1 key commitment";
/// Plaintext bytes per payload chunk; only the last chunk may be shorter.
const CHUNK_LEN: usize = 64 * 1024;
const TAG_LEN: usize = 16;

/// Encrypts everything read from `plaintext` to `recipient` and writes the container to
/// `ciphertext`.
///
/// # Errors
/// [`Error::Io`] if reading or writing fails, [`Error::Rng`] if the operating system cannot
/// supply random bytes. Whatever was written before an error is not a usable container.
pub fn encrypt(
    recipient: &PublicKey,
    plaintext: impl Read,
    ciphertext: impl Write,
) -> Result<(), Error> {
    let mut randomness = Zeroizing::new([0u8; ENCAPSULATION_RANDOMNESS_SIZE]);
    getrandom::fill(randomness.as_mut_slice())?;
    encrypt_with_randomness(recipient, &randomness, plaintext, ciphertext)
}

/// The deterministic core of [`encrypt`]. `randomness` must be fresh, uniform and secret for
/// every container: reusing it for two messages reuses the payload key and nonces.
fn encrypt_with_randomness(
    recipient: &PublicKey,
    randomness: &[u8; ENCAPSULATION_RANDOMNESS_SIZE],
    plaintext: impl Read,
    mut ciphertext: impl Write,
) -> Result<(), Error> {
    let (encapsulated_key, shared_secret) =
        recipient.0.encapsulate_deterministic(randomness.into());
    let shared_secret = Zeroizing::new(shared_secret);

    let mut header = [0u8; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[MAGIC.len()] = VERSION;
    header[PREAMBLE_LEN..].copy_from_slice(&encapsulated_key);

    let (cipher, commitment) = payload_keys(&shared_secret, &header, &recipient.0);
    ciphertext.write_all(&header)?;
    ciphertext.write_all(&commitment)?;

    let mut chunks = Chunks::new(plaintext, CHUNK_LEN)?;
    let mut index = 0u64;
    loop {
        let (mut chunk, is_last) = chunks.next_chunk()?;
        cipher
            .encrypt_in_place(&chunk_nonce(index, is_last), b"", &mut *chunk)
            .expect("a 64 KiB chunk is far below the ChaCha20-Poly1305 message limit");
        ciphertext.write_all(&chunk)?;
        if is_last {
            break;
        }
        index = index.checked_add(1).expect("no input has 2^64 chunks");
    }
    ciphertext.flush()?;
    Ok(())
}

/// Decrypts the container read from `ciphertext` with `key` and writes the message to
/// `plaintext`.
///
/// The message is released chunk by chunk, each one authenticated before it is written, but a
/// truncated or modified container is only detected when the damaged chunk is reached. On any
/// error the caller must therefore discard everything written to `plaintext` so far.
///
/// # Errors
/// [`Error::NotRiegel`] or [`Error::UnsupportedVersion`] if the input is not a version 1
/// container, [`Error::DecryptionFailed`] if the key is wrong or the container was truncated,
/// corrupted or tampered with, and [`Error::Io`] if reading or writing fails.
pub fn decrypt(
    key: &SecretKey,
    mut ciphertext: impl Read,
    mut plaintext: impl Write,
) -> Result<(), Error> {
    let mut header = [0u8; HEADER_LEN];
    let (preamble, encapsulated_key) = header.split_at_mut(PREAMBLE_LEN);

    read_exact_or(&mut ciphertext, preamble, Error::NotRiegel)?;
    if &preamble[..MAGIC.len()] != MAGIC {
        return Err(Error::NotRiegel);
    }
    let version = preamble[MAGIC.len()];
    if version != VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    read_exact_or(&mut ciphertext, encapsulated_key, Error::DecryptionFailed)?;
    let mut stored_commitment = [0u8; COMMITMENT_LEN];
    read_exact_or(
        &mut ciphertext,
        &mut stored_commitment,
        Error::DecryptionFailed,
    )?;

    let encapsulated_key = Ciphertext::try_from(&*encapsulated_key)
        .expect("the slice has the X-Wing ciphertext length");
    // Rejects an all-zero X25519 shared secret, which only a malformed container produces.
    let shared_secret = key
        .0
        .try_decapsulate(&encapsulated_key)
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)?;
    let (cipher, commitment) = payload_keys(&shared_secret, &header, key.0.encapsulation_key());
    if !bool::from(commitment.ct_eq(&stored_commitment)) {
        return Err(Error::DecryptionFailed);
    }

    let mut chunks = Chunks::new(ciphertext, CHUNK_LEN + TAG_LEN)?;
    let mut index = 0u64;
    loop {
        let (mut chunk, is_last) = chunks.next_chunk()?;
        cipher
            .decrypt_in_place(&chunk_nonce(index, is_last), b"", &mut *chunk)
            .map_err(|_| Error::DecryptionFailed)?;
        // Each message has exactly one encoding: only an empty message has an empty chunk.
        if chunk.is_empty() && index > 0 {
            return Err(Error::DecryptionFailed);
        }
        plaintext.write_all(&chunk)?;
        if is_last {
            break;
        }
        index = index.checked_add(1).expect("no input has 2^64 chunks");
    }
    plaintext.flush()?;
    Ok(())
}

/// Derives the payload cipher and the commitment to its key.
///
/// Hashing the header and the recipient key into the derivation binds both values to this
/// exact container and recipient, independently of what the KEM itself guarantees. The
/// commitment is stored in the container: ChaCha20-Poly1305 alone would let a crafted payload
/// verify under more than one key, and the commitment rules that out.
fn payload_keys(
    shared_secret: &[u8],
    header: &[u8; HEADER_LEN],
    recipient: &EncapsulationKey,
) -> (ChaCha20Poly1305, [u8; COMMITMENT_LEN]) {
    const VALID_LEN: &str = "32 bytes is a valid HKDF-SHA-256 output length";

    let context = Sha256::new()
        .chain_update(header)
        .chain_update(recipient.to_bytes())
        .finalize();
    let kdf = Hkdf::<Sha256>::new(None, shared_secret);

    let mut key = Zeroizing::new([0u8; 32]);
    kdf.expand_multi_info(&[KEY_LABEL, &context], key.as_mut_slice())
        .expect(VALID_LEN);
    let mut commitment = [0u8; COMMITMENT_LEN];
    kdf.expand_multi_info(&[COMMITMENT_LABEL, &context], &mut commitment)
        .expect(VALID_LEN);
    (ChaCha20Poly1305::new((&*key).into()), commitment)
}

/// The nonce of a payload chunk: its index as an 11-byte big-endian integer, then one byte
/// that is 1 for the last chunk. Marking the last chunk is what makes truncation detectable.
fn chunk_nonce(index: u64, is_last: bool) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[3..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(is_last);
    nonce.into()
}

/// `read_exact`, with a premature end of input reported as `on_eof` instead of an I/O error.
fn read_exact_or(reader: &mut impl Read, buffer: &mut [u8], on_eof: Error) -> Result<(), Error> {
    reader
        .read_exact(buffer)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => on_eof,
            _ => Error::Io(error),
        })
}

/// Splits a reader into chunks of `chunk_len` bytes. It reads one chunk ahead so that each
/// chunk can be handed out together with whether it is the last one. An empty input yields a
/// single empty chunk, and a chunk that is not the last is always full.
struct Chunks<R> {
    reader: R,
    chunk_len: usize,
    pending: Zeroizing<Vec<u8>>,
}

impl<R: Read> Chunks<R> {
    fn new(mut reader: R, chunk_len: usize) -> io::Result<Self> {
        let pending = read_chunk(&mut reader, chunk_len)?;
        Ok(Self {
            reader,
            chunk_len,
            pending,
        })
    }

    /// Returns the next chunk and whether it is the last. Must not be called after the last.
    fn next_chunk(&mut self) -> io::Result<(Zeroizing<Vec<u8>>, bool)> {
        let following = if self.pending.len() == self.chunk_len {
            read_chunk(&mut self.reader, self.chunk_len)?
        } else {
            Zeroizing::new(Vec::new())
        };
        let is_last = following.is_empty();
        Ok((mem::replace(&mut self.pending, following), is_last))
    }
}

fn read_chunk(reader: &mut impl Read, chunk_len: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    // Room for the tag, so that sealing a plaintext chunk in place never reallocates and
    // leaves an unwiped copy behind.
    let mut chunk = Zeroizing::new(Vec::with_capacity(chunk_len + TAG_LEN));
    reader.take(chunk_len as u64).read_to_end(&mut chunk)?;
    Ok(chunk)
}

#[cfg(test)]
mod tests;
