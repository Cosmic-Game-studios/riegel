# Third-party components

The Riegel license (`LICENSE`) covers the files of this repository. It does not cover, and does
not change the terms of, the components below.

## Libraries

Riegel is built on these libraries. They are not part of this repository; Cargo downloads them
at build time, in the exact versions recorded in `Cargo.lock`. A compiled `riegel` binary
contains code from them, so anyone who passes a binary on must also pass on their license
texts and copyright notices.

| Library | Purpose | License |
|---|---|---|
| `x-wing` | X-Wing hybrid KEM | Apache-2.0 OR MIT |
| `ml-kem`, `module-lattice` | ML-KEM-768 (FIPS 203) | Apache-2.0 OR MIT |
| `x25519-dalek`, `curve25519-dalek` | X25519 | BSD-3-Clause |
| `chacha20poly1305`, `chacha20`, `poly1305`, `aead` | ChaCha20-Poly1305 | Apache-2.0 OR MIT |
| `hkdf`, `hmac`, `sha2` | HKDF-SHA-256 | MIT OR Apache-2.0 |
| `sha3`, `shake`, `keccak` | SHA-3 and SHAKE, used inside X-Wing | MIT OR Apache-2.0 |
| `getrandom` | Random bytes from the operating system | MIT OR Apache-2.0 |
| `argon2`, `blake2` | Argon2id for the passphrase-protected secret key | MIT OR Apache-2.0 |
| `rpassword`, `rtoolbox` | Reading a passphrase without showing it | Apache-2.0 |
| `base64ct` | Constant-time Base64 for key text | Apache-2.0 OR MIT |
| `zeroize` | Wiping secrets from memory | Apache-2.0 OR MIT |
| `subtle` | Constant-time helpers | BSD-3-Clause |

### Complete list

Every package recorded in `Cargo.lock`, with the license it declares. The list covers the
packages compiled into the tool, those used only while building or testing (`serde_json`,
`hex` and what they need), and those Cargo records for other platforms. All are under
MIT, Apache-2.0 or both, with these exceptions: `curve25519-dalek`, `x25519-dalek` and
`subtle` are BSD-3-Clause; `unicode-ident` additionally carries Unicode-3.0; `memchr` is
Unlicense OR MIT; `fiat-crypto` and `r-efi` offer a third alternative besides MIT and
Apache-2.0.

Regenerate the list after changing dependencies:
`cargo metadata --format-version 1 --locked`.

| Package | Version | License |
|---|---|---|
| `aead` | 0.6.1 | MIT OR Apache-2.0 |
| `argon2` | 0.6.0 | MIT OR Apache-2.0 |
| `autocfg` | 1.5.1 | Apache-2.0 OR MIT |
| `base64ct` | 1.8.3 | Apache-2.0 OR MIT |
| `blake2` | 0.11.0 | MIT OR Apache-2.0 |
| `block-buffer` | 0.12.1 | MIT OR Apache-2.0 |
| `cfg-if` | 1.0.5 | MIT OR Apache-2.0 |
| `chacha20` | 0.10.2 | MIT OR Apache-2.0 |
| `chacha20poly1305` | 0.11.0 | Apache-2.0 OR MIT |
| `cipher` | 0.5.2 | MIT OR Apache-2.0 |
| `cmov` | 0.5.4 | Apache-2.0 OR MIT |
| `const-oid` | 0.10.3 | Apache-2.0 OR MIT |
| `cpufeatures` | 0.3.1 | MIT OR Apache-2.0 |
| `crypto-common` | 0.2.2 | MIT OR Apache-2.0 |
| `ctutils` | 0.4.8 | Apache-2.0 OR MIT |
| `curve25519-dalek` | 5.0.0 | BSD-3-Clause |
| `curve25519-dalek-derive` | 0.1.1 | MIT/Apache-2.0 |
| `der` | 0.8.3 | Apache-2.0 OR MIT |
| `digest` | 0.11.3 | MIT OR Apache-2.0 |
| `fiat-crypto` | 0.3.0 | MIT OR Apache-2.0 OR BSD-1-Clause |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 |
| `hex` | 0.4.3 | MIT OR Apache-2.0 |
| `hkdf` | 0.13.0 | MIT OR Apache-2.0 |
| `hmac` | 0.13.0 | MIT OR Apache-2.0 |
| `hybrid-array` | 0.4.15 | MIT OR Apache-2.0 |
| `inout` | 0.2.6 | MIT OR Apache-2.0 |
| `itoa` | 1.0.19 | MIT OR Apache-2.0 |
| `keccak` | 0.2.2 | Apache-2.0 OR MIT |
| `kem` | 0.3.0 | Apache-2.0 OR MIT |
| `libc` | 0.2.191 | MIT OR Apache-2.0 |
| `memchr` | 2.8.3 | Unlicense OR MIT |
| `ml-kem` | 0.3.4 | Apache-2.0 OR MIT |
| `module-lattice` | 0.2.4 | Apache-2.0 OR MIT |
| `num-traits` | 0.2.19 | MIT OR Apache-2.0 |
| `password-hash` | 0.6.1 | MIT OR Apache-2.0 |
| `phc` | 0.6.1 | Apache-2.0 OR MIT |
| `pkcs8` | 0.11.0 | Apache-2.0 OR MIT |
| `poly1305` | 0.9.1 | Apache-2.0 OR MIT |
| `proc-macro2` | 1.0.107 | MIT OR Apache-2.0 |
| `quote` | 1.0.47 | MIT OR Apache-2.0 |
| `r-efi` | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| `rand_core` | 0.10.1 | MIT OR Apache-2.0 |
| `rpassword` | 7.5.5 | Apache-2.0 |
| `rtoolbox` | 0.0.6 | Apache-2.0 |
| `rustc_version` | 0.4.1 | MIT OR Apache-2.0 |
| `semver` | 1.0.28 | MIT OR Apache-2.0 |
| `serde` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_core` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_derive` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 |
| `sha2` | 0.11.1 | MIT OR Apache-2.0 |
| `sha3` | 0.12.0 | MIT OR Apache-2.0 |
| `shake` | 0.1.0 | MIT OR Apache-2.0 |
| `spki` | 0.8.1 | Apache-2.0 OR MIT |
| `sponge-cursor` | 0.1.0 | MIT OR Apache-2.0 |
| `subtle` | 2.6.1 | BSD-3-Clause |
| `syn` | 2.0.119 | MIT OR Apache-2.0 |
| `syn` | 3.0.10 | MIT OR Apache-2.0 |
| `typenum` | 1.20.1 | MIT OR Apache-2.0 |
| `unicode-ident` | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| `universal-hash` | 0.6.1 | MIT OR Apache-2.0 |
| `windows-link` | 0.2.1 | MIT OR Apache-2.0 |
| `windows-sys` | 0.61.2 | MIT OR Apache-2.0 |
| `x-wing` | 0.1.1 | Apache-2.0 OR MIT |
| `x25519-dalek` | 3.0.0 | BSD-3-Clause |
| `zeroize` | 1.9.2 | Apache-2.0 OR MIT |
| `zmij` | 1.0.23 | MIT |

## Test data

`tests/vectors/x-wing-draft.json` holds the test vectors of the X-Wing specification
(draft-connolly-cfrg-xwing-kem, `spec/test-vectors.json`). The file is copied unchanged from
the `x-wing` crate, version 0.1.1 (Apache-2.0 OR MIT).
