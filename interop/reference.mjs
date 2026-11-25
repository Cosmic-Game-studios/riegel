// Independent reference implementation of the reading side of Riegel v1: decrypting a
// container, opening a passphrase-protected secret key and computing a fingerprint.
//
// Written from SPEC.md on top of Node's built-in crypto (OpenSSL). It shares no code with the
// Rust implementation, so agreement between the two is evidence that SPEC.md is complete and
// that both follow it. Needs Node.js 24.7 or newer (ML-KEM and Argon2 support). Not for
// production use: it keeps the whole container in memory and makes no attempt to wipe secrets.

import {
  argon2Sync,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  decapsulate,
  diffieHellman,
  hkdfSync,
  timingSafeEqual,
} from 'node:crypto';

const MAGIC = Buffer.from('RIEGEL');
const VERSION = 1;
const ML_KEM_CIPHERTEXT_LEN = 1088;
const ML_KEM_PUBLIC_KEY_LEN = 1184;
const X25519_LEN = 32;
const HEADER_LEN = MAGIC.length + 1 + ML_KEM_CIPHERTEXT_LEN + X25519_LEN;
const COMMITMENT_LEN = 32;
const CHUNK_LEN = 65536;
const TAG_LEN = 16;
const KEY_LABEL = Buffer.from('riegel v1 payload key');
const COMMITMENT_LABEL = Buffer.from('riegel v1 key commitment');
const X_WING_LABEL = Buffer.from('5c2e2f2f5e5c', 'hex'); // \.//^\

const PUBLIC_KEY_PREFIX = 'riegel-pub-1:';
const SECRET_KEY_PREFIX = 'riegel-sec-1:';
const PROTECTED_KEY_PREFIX = 'riegel-sec-pw-1:';
const SEED_LEN = 32;
const SALT_LEN = 16;

// DER wrappers around raw key bytes, so that OpenSSL accepts them.
const ML_KEM_768_SEED_PKCS8 = Buffer.from('3054020100300b060960864801650304040204428040', 'hex');
const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');

const FAILED = 'decryption failed';

/**
 * Decrypts a Riegel v1 container (Buffer) and returns the message. `secretKeyText` is a
 * secret key in plain text form; open a protected one with `openProtectedSecretKey` first.
 */
export function decrypt(secretKeyText, container) {
  const keys = xWingKeys(parseSecretKey(secretKeyText));

  if (container.length < MAGIC.length + 1 || !container.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('not a Riegel file');
  }
  if (container[MAGIC.length] !== VERSION) {
    throw new Error(`unsupported Riegel format version ${container[MAGIC.length]}`);
  }
  if (container.length < HEADER_LEN + COMMITMENT_LEN) throw new Error(FAILED);
  const header = container.subarray(0, HEADER_LEN);
  const storedCommitment = container.subarray(HEADER_LEN, HEADER_LEN + COMMITMENT_LEN);
  const payload = container.subarray(HEADER_LEN + COMMITMENT_LEN);

  const sharedSecret = xWingDecapsulate(keys, header.subarray(MAGIC.length + 1));
  const context = createHash('sha256').update(header).update(keys.publicKey).digest();
  const derive = (label) =>
    Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.concat([label, context]), 32));
  const key = derive(KEY_LABEL);
  if (!timingSafeEqual(derive(COMMITMENT_LABEL), storedCommitment)) throw new Error(FAILED);

  const sealedChunkLen = CHUNK_LEN + TAG_LEN;
  const chunkCount = Math.max(1, Math.ceil(payload.length / sealedChunkLen));
  const message = [];
  for (let index = 0; index < chunkCount; index += 1) {
    const sealed = payload.subarray(index * sealedChunkLen, (index + 1) * sealedChunkLen);
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64BE(BigInt(index), 3);
    nonce[11] = index === chunkCount - 1 ? 1 : 0;
    const chunk = open(key, nonce, Buffer.alloc(0), sealed, FAILED);
    if (chunk.length === 0 && index > 0) throw new Error(FAILED);
    message.push(chunk);
  }
  return Buffer.concat(message);
}

/** Opens a passphrase-protected secret key and returns it in plain text form. */
export function openProtectedSecretKey(protectedKeyText, passphrase) {
  const data = decodeKey(protectedKeyText, PROTECTED_KEY_PREFIX, SALT_LEN + SEED_LEN + TAG_LEN);
  if (passphrase.length === 0) throw new Error('the passphrase must not be empty');

  const wrappingKey = argon2Sync('argon2id', {
    message: Buffer.from(passphrase, 'utf8'),
    nonce: data.subarray(0, SALT_LEN),
    memory: 65536, // KiB
    passes: 3,
    parallelism: 4,
    tagLength: 32,
  });
  const seed = open(
    Buffer.from(wrappingKey),
    Buffer.alloc(12),
    Buffer.from(PROTECTED_KEY_PREFIX),
    data.subarray(SALT_LEN),
    'wrong passphrase, or the secret key is damaged',
  );
  return SECRET_KEY_PREFIX + seed.toString('base64');
}

/** The fingerprint of a public key in text form. */
export function fingerprint(publicKeyText) {
  const publicKey = decodeKey(publicKeyText, PUBLIC_KEY_PREFIX, ML_KEM_PUBLIC_KEY_LEN + X25519_LEN);
  return createHash('sha256').update(publicKey).digest('hex').match(/.{4}/g).join(' ');
}

function parseSecretKey(text) {
  return decodeKey(text, SECRET_KEY_PREFIX, SEED_LEN);
}

function decodeKey(text, prefix, length) {
  const trimmed = text.trim();
  if (!trimmed.startsWith(prefix)) throw new Error(`not a key starting with ${prefix}`);
  const data = Buffer.from(trimmed.slice(prefix.length), 'base64');
  if (data.length !== length) throw new Error('the key has the wrong length');
  return data;
}

// X-Wing key generation from the 32-byte seed (draft-connolly-cfrg-xwing-kem, section 5.2).
function xWingKeys(seed) {
  const expanded = createHash('shake256', { outputLength: 96 }).update(seed).digest();
  const mlKem = createPrivateKey({
    key: Buffer.concat([ML_KEM_768_SEED_PKCS8, expanded.subarray(0, 64)]),
    format: 'der',
    type: 'pkcs8',
  });
  const x25519 = createPrivateKey({
    key: Buffer.concat([X25519_PKCS8, expanded.subarray(64, 96)]),
    format: 'der',
    type: 'pkcs8',
  });
  // The raw public key is the tail of its DER encoding.
  const rawPublicKey = (privateKey, length) =>
    createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-length);
  const x25519PublicKey = rawPublicKey(x25519, X25519_LEN);
  return {
    mlKem,
    x25519,
    x25519PublicKey,
    publicKey: Buffer.concat([rawPublicKey(mlKem, ML_KEM_PUBLIC_KEY_LEN), x25519PublicKey]),
  };
}

// X-Wing decapsulation (section 5.5), plus the all-zero check that Riegel adds.
function xWingDecapsulate(keys, ciphertext) {
  const mlKemCiphertext = ciphertext.subarray(0, ML_KEM_CIPHERTEXT_LEN);
  const x25519Share = ciphertext.subarray(ML_KEM_CIPHERTEXT_LEN);

  const mlKemSecret = decapsulate(keys.mlKem, mlKemCiphertext);
  let x25519Secret;
  try {
    x25519Secret = diffieHellman({
      privateKey: keys.x25519,
      publicKey: createPublicKey({
        key: Buffer.concat([X25519_SPKI, x25519Share]),
        format: 'der',
        type: 'spki',
      }),
    });
  } catch {
    throw new Error(FAILED); // OpenSSL refuses shares that give an all-zero secret.
  }
  if (x25519Secret.every((byte) => byte === 0)) throw new Error(FAILED);

  return createHash('sha3-256')
    .update(mlKemSecret)
    .update(x25519Secret)
    .update(x25519Share)
    .update(keys.x25519PublicKey)
    .update(X_WING_LABEL)
    .digest();
}

// ChaCha20-Poly1305 decryption of `sealed` (ciphertext followed by the tag).
function open(key, nonce, associatedData, sealed, failure) {
  if (sealed.length < TAG_LEN) throw new Error(failure);
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: TAG_LEN });
  decipher.setAAD(associatedData);
  decipher.setAuthTag(sealed.subarray(sealed.length - TAG_LEN));
  try {
    return Buffer.concat([
      decipher.update(sealed.subarray(0, sealed.length - TAG_LEN)),
      decipher.final(),
    ]);
  } catch {
    throw new Error(failure);
  }
}
