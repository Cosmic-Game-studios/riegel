# Riegel

Hybrid post-quantum file encryption. *Riegel* is German for the bolt on a door.

Deutsche Fassung: [README.de.md](README.de.md)

> **Experimental and unaudited.** Nobody independent of the authors has reviewed the design or
> the code. Do not rely on Riegel for data that matters; see [SECURITY.md](SECURITY.md).

> **Not open source.** The source is published to be read and examined. Commercial use and
> military use are not permitted; see [License](#license).

## What it does

Riegel encrypts a file to a public key. Only the holder of the matching secret key can decrypt
it, and any change to the encrypted file is detected.

The key exchange combines a post-quantum algorithm with a classical one, so a file stays
confidential as long as **either** of them holds. That covers an attacker who stores encrypted
files today to decrypt them with a quantum computer later.

Riegel does not invent cryptography. It puts published building blocks together:

| Purpose | Algorithm |
|---|---|
| Key exchange | X-Wing: ML-KEM-768 (FIPS 203) combined with X25519 |
| Key derivation | HKDF-SHA-256 |
| File encryption | ChaCha20-Poly1305 in 64 KiB chunks, with truncation detection |
| Secret key file | Encrypted under a passphrase with Argon2id and ChaCha20-Poly1305 |

[SPEC.md](SPEC.md) describes the format completely, down to the byte.

## Usage

Build with Rust 1.88 or newer:

```sh
cargo build --release
```

The tool is then at `target/release/riegel`.

```sh
# Once: create a key pair. You choose a passphrase, which encrypts my.key.
# Keep my.key secret, hand my.pub to anyone who should write to you.
riegel keygen my.key my.pub

# Before encrypting to a key you were sent, compare this with its owner.
riegel fingerprint my.pub

# Anyone with my.pub can encrypt to you.
riegel encrypt my.pub report.pdf report.pdf.riegel

# Only my.key, together with its passphrase, can decrypt.
riegel decrypt my.key report.pdf.riegel report.pdf
```

Riegel never overwrites an existing file. It exits with 0 on success, 1 on failure and 2 when
called with the wrong arguments. If decryption fails, no output file is left behind.

The passphrase is asked for on the terminal and is not shown. When standard input is not a
terminal, its first line is taken as the passphrase, byte for byte; if it contains non-ASCII
characters, type it at the prompt, because a shell may re-encode piped text.
`riegel keygen --no-passphrase` writes an unencrypted secret key for unattended machines.

An encrypted file is 1159 bytes larger than the original, plus 16 bytes per 64 KiB.

### As a library

```rust
let secret = riegel::SecretKey::generate()?;
let recipient = secret.public_key();

let mut sealed = Vec::new();
riegel::encrypt(&recipient, &b"attack at dawn"[..], &mut sealed)?;

let mut opened = Vec::new();
riegel::decrypt(&secret, &sealed[..], &mut opened)?;
```

`encrypt` and `decrypt` work on any reader and writer, so large files are processed in
constant memory.

## What it does not do

- It does not tell you who encrypted a file. Anyone with your public key can encrypt to you.
- It has no forward secrecy. If your secret key leaks, every file ever encrypted to it can be
  read.
- It does not verify public keys for you. Compare the fingerprint with the recipient over a
  channel you trust.
- It does not hide the size of a file.
- The secret key file is only as safe as its passphrase is hard to guess.
- One file has one recipient.

[SECURITY.md](SECURITY.md) and section 8 of [SPEC.md](SPEC.md) explain these limits.

## How it is checked

```sh
cargo test
```

runs the building blocks against the test vectors of their specifications (X-Wing draft,
RFC 5869, RFC 8439, RFC 9106), encryption and key protection bit for bit against the vectors
in `tests/vectors/riegel-v1.json`, every single-bit change and every truncation of an
encrypted file, further manipulated files, and the command-line tool end to end.

```sh
node interop/check.mjs target/release/riegel
```

reads what the tool produces (encrypted files, the passphrase-protected key, the fingerprint)
with a second implementation that shares no code with the first: `interop/reference.mjs`,
written from the specification on top of OpenSSL. It needs Node.js 24.7 or newer.

## License

Riegel is **source-available, not open source**. Under the [Riegel Source-Available
License 1.0](LICENSE) you may read, build, run and modify it for private, educational and
research purposes. You may not use it commercially, you may not use it for military purposes,
and you may not redistribute it. All other rights are reserved by the copyright holder; ask
them if you need a different license.

The libraries Riegel builds on have their own, permissive licenses; see
[THIRD-PARTY.md](THIRD-PARTY.md).
