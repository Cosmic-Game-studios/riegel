# Security

## Status

Riegel is experimental. Neither the design in `SPEC.md` nor this implementation has been
reviewed or audited by anyone independent of its authors. Do not use it to protect data whose
exposure or loss would cause real harm. For that, use an established, widely reviewed tool
such as [age](https://age-encryption.org).

Riegel invents no cryptographic primitive; it combines published ones. That lowers the risk
but does not remove it: mistakes in how primitives are combined, and in the code around them,
are a common cause of broken encryption.

## What Riegel protects, and what it does not

Riegel keeps a file confidential and detects any modification of it, against an attacker who
does not have the recipient's secret key. Because it combines ML-KEM-768 with X25519, this
holds as long as one of the two remains secure. That includes an attacker who records
encrypted files today in order to decrypt them with a future quantum computer.

It does **not**

- tell you who encrypted a file: anyone with your public key can encrypt to you;
- protect past files once your secret key leaks: there is no forward secrecy;
- protect you from a swapped public key on its own: if an attacker gets their own key to the
  sender in place of yours, they read the file. Compare the fingerprint
  (`riegel fingerprint`) over a channel you trust;
- hide the size of a file, or that a file was encrypted with Riegel;
- protect a secret key whose passphrase can be guessed. The key file is encrypted under the
  passphrase with Argon2id, which slows guessing down but cannot rescue a weak passphrase. A
  key made with `--no-passphrase` is not encrypted at all. On Unix the tool creates the file
  readable by its owner only; on Windows it gets the permissions of its folder;
- wipe secrets reliably: key material is zeroed in memory on a best-effort basis, but the
  operating system may have copied it (swap, crash dumps), and decrypted files are ordinary
  files.

`SPEC.md`, section 8, has the complete list with the reasoning.

## Dependencies

All cryptography comes from the RustCrypto and dalek libraries listed in `THIRD-PARTY.md`;
the hidden passphrase prompt comes from `rpassword`. Their side-channel behaviour is inherited
as is. According to their own documentation, the `ml-kem` and `x-wing` crates have not been
independently audited. X-Wing itself is still an Internet-Draft, not a finished standard.

## How this implementation is checked

- The building blocks are tested against the vectors of their specifications: the X-Wing
  draft, RFC 5869 (HKDF), RFC 8439 (ChaCha20-Poly1305) and RFC 9106 (Argon2id).
- Encryption and the passphrase protection of the secret key are tested bit for bit against
  the vectors in `tests/vectors/riegel-v1.json`.
- Every single-bit change and every truncation of a sample container must be rejected.
  Further cases cover a container missing its last chunk, appended data, reordered chunks, a
  non-canonical final chunk, a changed key commitment, an all-zero X25519 share and the wrong
  key; for the protected key, a wrong passphrase and modified salt, ciphertext and tag.
- `interop/reference.mjs` reads containers, protected keys and fingerprints with a separate
  implementation built on OpenSSL, which shares no code with the Rust one.

Tests show that the code does what the specification says. They do not show that the
specification is secure.

## Reporting a vulnerability

Please report security problems privately, through "Report a vulnerability" on the Security
tab of the GitHub repository, and not in a public issue. Include what you found, how to
reproduce it and which version you tested.
