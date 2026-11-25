# Riegel v1 specification

Status: experimental. Neither this design nor its implementation has been independently
reviewed. See `SECURITY.md`.

This document is normative. The key words MUST, MUST NOT and MAY are used as in RFC 2119.

## 1. Overview

Riegel encrypts a message (any byte string, typically a file) so that only the holder of a
secret key can read it. The sender needs nothing but the recipient's public key. One container
has exactly one recipient.

Riegel defines no new cryptographic primitive. It combines published ones:

| Purpose | Algorithm | Reference |
|---|---|---|
| Key encapsulation | X-Wing: ML-KEM-768 combined with X25519 | draft-connolly-cfrg-xwing-kem-11, FIPS 203, RFC 7748 |
| Key derivation | HKDF-SHA-256 | RFC 5869 |
| Hash | SHA-256 | FIPS 180-4 |
| Payload encryption | ChaCha20-Poly1305 | RFC 8439 |
| Chunking | STREAM | Hoang, Reyhanitabar, Rogaway, Vizár: *Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance*, CRYPTO 2015 |
| Key from a passphrase | Argon2id | RFC 9106 |

What Riegel itself specifies is how these are put together: the text forms of keys, including
the passphrase-protected secret key and the fingerprint (section 3), the container layout
(section 4), the derivation of the payload key and its commitment (section 5), and the rules
for encryption and decryption (sections 6 and 7).

## 2. Notation

- `a || b` is the concatenation of the byte strings `a` and `b`.
- `x[i:j]` is the part of `x` from byte `i` (inclusive) to byte `j` (exclusive), counting from 0.
- Text in double quotes is ASCII without a terminator.
- `I2OSP(n, len)` is the integer `n` as `len` bytes, most significant byte first.
- X-Wing functions are named as in the draft: `GenerateKeyPairDerand(sk)`,
  `EncapsulateDerand(pk, eseed)`, `Decapsulate(ct, sk)`.

## 3. Keys

### 3.1 Key pair

A secret key `sk` is 32 bytes drawn uniformly at random from a cryptographically secure
generator. It is the X-Wing decapsulation key.

The public key `pk` is the 1216-byte X-Wing encapsulation key computed from `sk` by
`GenerateKeyPairDerand(sk)` (section 5.2 of the draft): `sk` is expanded with SHAKE-256 to 96
bytes, of which bytes 0 to 63 seed ML-KEM-768 key generation and bytes 64 to 95 are the X25519
secret key. `pk` is the ML-KEM-768 encapsulation key (1184 bytes) followed by the X25519 public
key (32 bytes).

### 3.2 Text forms

| Key | Text form | Length |
|---|---|---|
| Public | `"riegel-pub-1:" \|\| Base64(pk)` | 1637 characters |
| Secret, protected | `"riegel-sec-pw-1:" \|\| Base64(salt \|\| sealed)`, see 3.3 | 104 characters |
| Secret, plain | `"riegel-sec-1:" \|\| Base64(sk)` | 57 characters |

Base64 is the standard alphabet of RFC 4648, section 4, with padding.

A reader MUST ignore ASCII whitespace before and after the text form and MUST reject

- text that does not start with the prefix of the expected kind of key,
- Base64 that is not canonical (wrong padding, non-zero unused bits, characters outside the
  alphabet, embedded whitespace),
- data whose decoded length is not exactly 1216 bytes (public), 64 bytes (secret, protected)
  or 32 bytes (secret, plain),
- a public key whose ML-KEM part fails the modulus check of FIPS 203, section 7.2.

A key file holds the text form followed by a line feed.

The plain form gives the secret key to anyone who can read it. It exists for machines where
nobody can enter a passphrase; a tool MUST NOT write it unless explicitly asked to.

### 3.3 Passphrase-protected secret key

The passphrase is a non-empty text. It is used as its UTF-8 encoding exactly as given: it is
not normalized, trimmed or changed in case. An empty passphrase MUST be rejected.

```
salt     = 16 bytes, uniformly random, fresh for every protected key
wrap_key = Argon2id(password = passphrase, salt = salt,
                    passes t = 3, memory m = 65536 KiB, lanes p = 4, tag length 32,
                    version 0x13, no secret, no associated data)
sealed   = ChaCha20-Poly1305-Encrypt(wrap_key, nonce = 12 zero bytes,
                                     aad = "riegel-sec-pw-1:", sk)
text     = "riegel-sec-pw-1:" || Base64(salt || sealed)
```

`sealed` is 48 bytes: the encrypted `sk` followed by the 16-byte tag. The Argon2id parameters
are the second recommended set of RFC 9106, section 4. They are fixed by the prefix. A reader
MUST NOT take them from anywhere else.

To open a protected key, a reader derives `wrap_key` from the passphrase and the stored salt
and decrypts `sealed`. If the tag does not verify, it fails with one error that does not
distinguish a wrong passphrase from damaged or modified key text.

### 3.4 Fingerprint

The fingerprint of a public key is SHA-256(`pk`), computed over the 1216 key bytes, written as
64 lowercase hexadecimal digits in sixteen groups of four, separated by single spaces:

```
c9a3 565f fde4 f72b 5166 1be3 91ee 13e4 6378 d7f0 6dd5 c8bf 5af9 d2cf b5b8 336b
```

It exists so that two people can check, over a channel they trust, that they hold the same
public key. The whole fingerprint has to be compared.

## 4. Container

```
offset  length  field
     0       6  magic       "RIEGEL"  (52 49 45 47 45 4c)
     6       1  version     0x01
     7    1120  kem_ct      X-Wing ciphertext: ML-KEM-768 ciphertext (1088 bytes)
                            followed by the X25519 share (32 bytes)
  1127      32  commitment  commitment to the payload key (section 5)
  1159       *  payload     one or more sealed chunks
```

The first 1127 bytes, up to but not including the commitment, are the `header`.

### 4.1 Payload

Let `C` = 65536. The message `M` of `n` bytes is split into `k` chunks `M_0 ... M_{k-1}`:

- if `n` = 0, there is one chunk and it is empty (`k` = 1);
- otherwise `k` = ceil(`n` / `C`): every chunk except the last holds exactly `C` bytes and the
  last holds between 1 and `C` bytes.

This makes the split unique: a message has exactly one encoding.

Chunk `i` is sealed with ChaCha20-Poly1305 under the payload `key` of section 5, with empty
associated data:

```
nonce_i  = I2OSP(i, 11) || last_i        last_i = 0x01 if i = k-1, else 0x00
sealed_i = ChaCha20-Poly1305-Encrypt(key, nonce_i, aad = "", M_i)
```

`sealed_i` is the ciphertext of `M_i` followed by the 16-byte tag. The payload is
`sealed_0 || ... || sealed_{k-1}`. A container is therefore 1159 + `n` + 16·`k` bytes long.

## 5. Payload key and commitment

Let `ss` be the 32-byte X-Wing shared secret and `pk` the recipient's public key.

```
context    = SHA-256(header || pk)
key        = HKDF-SHA-256(IKM = ss, salt = "", info = "riegel v1 payload key" || context, L = 32)
commitment = HKDF-SHA-256(IKM = ss, salt = "", info = "riegel v1 key commitment" || context, L = 32)
```

The two labels are 21 and 24 ASCII bytes. An empty salt is the HKDF default of 32 zero bytes.

## 6. Encryption

Input: the recipient's public key `pk` and the message `M`.

1. Draw `eseed`, 64 bytes, uniformly at random from a cryptographically secure generator.
2. `(ss, kem_ct) = EncapsulateDerand(pk, eseed)`.
3. Build the `header` and derive `key` and `commitment` (sections 4 and 5).
4. Output the `header`, the `commitment` and the sealed chunks of `M` (section 4.1).

`eseed` MUST be fresh for every container and MUST NOT be stored or disclosed. Using the same
`eseed` twice for one recipient repeats the payload key together with its nonces, which
reveals the XOR of the two messages and allows forgeries.

## 7. Decryption

Input: the secret key `sk` and a container.

1. If the container has fewer than 7 bytes or does not start with the magic, fail: it is not
   a Riegel container. If the version byte is not 0x01, fail: the version is unsupported.
2. If fewer than 1152 further bytes follow, fail. Otherwise the first 1120 of them are
   `kem_ct` and the next 32 are the stored commitment.
3. `ss = Decapsulate(kem_ct, sk)`, with one additional rule: if the X25519 function inside
   the decapsulation returns 32 zero bytes, decryption MUST fail. (The X-Wing draft is silent
   on this case and RFC 7748 leaves the check optional; Riegel fixes the behaviour so that all
   implementations accept exactly the same containers.)
4. Compute `pk` from `sk` and derive `key` and `commitment` (section 5). If `commitment`
   differs from the stored commitment, fail. The comparison MUST NOT depend on where the two
   values differ (constant time), and no chunk is opened before it has succeeded.
5. Split the rest of the container into sealed chunks of `C` + 16 bytes; only the last one may
   be shorter. If nothing follows the commitment, or the last sealed chunk is shorter than 16
   bytes, fail.
6. Open sealed chunk `i` with `nonce_i`, where `last_i` is 0x01 exactly when no byte follows
   the chunk. If a tag does not verify, fail. If the opened chunk is empty and `i` > 0, fail.
7. The message is the concatenation of the opened chunks.

An implementation MUST NOT release the content of a chunk before its tag is verified. When
decryption fails at a later chunk, everything released so far MUST be treated as invalid: a
tool writes to a temporary file and deletes it on failure. Apart from step 1, an
implementation reports every failure in the same way and does not reveal which step failed.

## 8. Security considerations

### 8.1 What Riegel provides

**Confidentiality and integrity** of the message against an attacker who does not have the
secret key, including an attacker who can submit modified containers for decryption.

**Hybrid security.** X-Wing is designed so that its shared secret stays secret if *either*
ML-KEM-768 *or* X25519 is secure. ML-KEM-768 is expected to resist attackers with a quantum
computer (NIST security category 3); X25519 protects against the possibility that ML-KEM or
its implementation turns out to be weak. The precise statement and its proof are in Barbosa
et al., *X-Wing: The Hybrid KEM You've Been Looking For* (IACR ePrint 2024/039).

**Detection of every change to the container.** Changing the header changes `context` and
therefore the payload key and the commitment. Changing, reordering, duplicating, dropping or
appending chunks changes the position or the last-chunk flag that a tag was computed for. In
particular, a container cut off at a chunk boundary does not verify, because its final chunk
was sealed with `last` = 0x00.

**One key per container.** A container that opens under one secret key does not open under a
different one. ChaCha20-Poly1305 alone does not guarantee this, which is why the container
carries the `commitment`: two different secret keys give different `context` values, and a
container valid for both would need the same 32-byte commitment from both, that is, a
collision in HMAC-SHA-256.

**A secret key file that is useless without its passphrase,** to the extent that the
passphrase is hard to guess (section 8.3).

### 8.2 What Riegel does not provide

- **No sender authentication.** Anyone who knows the public key can create a valid container.
  A container proves nothing about who made it. Sign the message separately if that matters.
- **No forward secrecy.** Whoever obtains the secret key can decrypt every container ever
  made for it, including ones recorded long before. This is inherent in encrypting a file to
  a long-lived key without any exchange with the recipient.
- **No automatic check of public keys.** An attacker who replaces the public key with their
  own before it reaches the sender reads the message. The fingerprint (section 3.4) lets
  sender and recipient detect this, but only if they compare it over a channel they trust.
- **No hiding of the message length** (the container length reveals it exactly), of the fact
  that a file is a Riegel container, or of file names and other metadata.
- **No claim of recipient anonymity.** A container does not contain the public key, but
  nothing here argues that containers for different recipients are indistinguishable.
- **No protection against a guessable passphrase,** and none at all for a secret key stored
  in plain form.
- **No side-channel guarantees beyond those of the implementation** and its libraries.

### 8.3 Design notes

*Nonces.* The payload key is derived from a fresh encapsulation, so it is used for one
container only, and within a container every chunk has a distinct nonce. A (key, nonce) pair
is never used twice as long as `eseed` is fresh.

*Binding.* `context` puts the format version, the KEM ciphertext and the recipient's public key
into the key derivation. X-Wing already binds the X25519 parts and relies on properties of
ML-KEM for the rest; hashing the whole header and public key makes the binding explicit and
independent of those properties, at the cost of one hash.

*No algorithm agility.* The version byte selects the entire construction. There are no
negotiable parameters, so there is nothing to downgrade. The same holds for the protected
key: its Argon2id parameters cannot be lowered by editing the key text.

*Limits.* A chunk is far below the ChaCha20-Poly1305 limit of about 256 GiB per nonce.
RFC 8439 (section 4) states that Poly1305 rejects a forged message of 16·m bytes with
probability 1 - m/2^102; for a full chunk (m = 4096) a forgery attempt therefore succeeds with
a chance of about 2^-90. The chunk index allows more chunks than can be processed in practice;
an implementation MAY restrict it to 64 bits.

*Passphrases.* Whoever obtains a protected key text can try passphrases offline, without
limit. Argon2id makes each attempt cost 64 MiB of memory and three passes over it, which slows
guessing but cannot save a passphrase that is short, common or reused. The wrapping key is
used once: it belongs to one freshly drawn salt and encrypts one secret key, which is why a
constant nonce is safe there. The prefix is authenticated as associated data, so protected
key text cannot be reinterpreted under another format version. Because the passphrase is not
normalized, the same characters entered in a different Unicode form are a different
passphrase.

*Relation to HPKE.* RFC 9180 with X-Wing as its KEM gives a comparable construction for short
messages. Riegel differs in the fixed container and in the chunked payload with truncation
detection, which is what encrypting large files needs.

### 8.4 Dependence on a draft

X-Wing is specified in an Internet-Draft, not yet in an RFC. Riegel v1 refers to version 11
of the draft (September 2026). The implementation is tested against the three test vectors in
Appendix C of that version. Should the final specification differ, Riegel v1 stays as defined
here and a new format version would adopt the change.

## 9. Test vectors

`tests/vectors/riegel-v1.json` contains:

- a key pair in text form (`secret_key`, plain, and `public_key`) and the fingerprint of the
  public key (`public_key_fingerprint`);
- `protected_secret_key`: the same secret key protected with the given `passphrase` and
  `salt`. Protecting with that salt MUST reproduce `text` exactly;
- `vectors`: containers for messages of 0, 13, 65535, 65536, 65537 and 131072 bytes. Byte `i`
  of every message is `i mod 251`. Each vector gives the `eseed` used
  (`encapsulation_randomness`), the container length and the SHA-256 of the container; the
  two shortest also give the complete container in hexadecimal. Encryption with the given
  `eseed` MUST reproduce the container bit for bit.

`interop/reference.mjs` is a second, independent implementation of the reading side
(decrypting a container, opening a protected key, computing a fingerprint), written from this
document on top of OpenSSL.

## 10. Versioning

Any change to this construction gets a new version byte, new derivation labels and new key
prefixes. An implementation MUST reject versions and prefixes it does not implement.
