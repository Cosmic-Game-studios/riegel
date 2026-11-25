// Cross-checks the Rust implementation against the independent reference implementation.
//
//   node interop/check.mjs <path to the riegel binary>
//
// 1. Published vectors: the fingerprint, the passphrase-protected secret key and every
//    container that is given in full must come out the same in the reference.
// 2. Keys and files made by the riegel binary, at sizes around the chunk boundaries, must be
//    readable by the reference: protected key, fingerprint and containers.
// 3. A truncated container, a modified one and one with a changed key commitment must be
//    refused by the reference.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { decrypt, fingerprint, openProtectedSecretKey } from './reference.mjs';

const [riegel, ...extra] = process.argv.slice(2);
if (!riegel || extra.length > 0) {
  console.error('usage: node interop/check.mjs <path to the riegel binary>');
  process.exit(2);
}

const HEADER_LEN = 1127;
const COMMITMENT_LEN = 32;
const SEALED_CHUNK_LEN = 65536 + 16;
const PASSPHRASE = 'Gegenprobe mit Umlaut: ü';
const patternPlaintext = (length) => Buffer.from(Array.from({ length }, (_, i) => i % 251));

const published = JSON.parse(
  readFileSync(new URL('../tests/vectors/riegel-v1.json', import.meta.url), 'utf8'),
);

assert.equal(fingerprint(published.public_key), published.public_key_fingerprint);
console.log('ok  published fingerprint');

const protectedKey = published.protected_secret_key;
assert.equal(
  openProtectedSecretKey(protectedKey.text, protectedKey.passphrase),
  published.secret_key,
);
console.log('ok  published passphrase-protected secret key');

const withCiphertext = published.vectors.filter((vector) => vector.ciphertext);
assert.ok(withCiphertext.length > 0, 'no published vector carries a ciphertext');
for (const vector of withCiphertext) {
  const message = decrypt(published.secret_key, Buffer.from(vector.ciphertext, 'hex'));
  assert.deepEqual(message, patternPlaintext(vector.plaintext_len), `vector "${vector.name}"`);
  console.log(`ok  published vector "${vector.name}"`);
}

const directory = mkdtempSync(join(tmpdir(), 'riegel-interop-'));
try {
  const secretKeyPath = join(directory, 'test.key');
  const publicKeyPath = join(directory, 'test.pub');
  // The binary takes the passphrase from standard input when it has no terminal.
  execFileSync(riegel, ['keygen', secretKeyPath, publicKeyPath], {
    input: `${PASSPHRASE}\n`,
    stdio: ['pipe', 'ignore', 'ignore'],
  });
  const secretKey = openProtectedSecretKey(readFileSync(secretKeyPath, 'utf8'), PASSPHRASE);
  console.log('ok  riegel keygen -> reference opens the protected secret key');

  const printed = execFileSync(riegel, ['fingerprint', publicKeyPath], { encoding: 'utf8' });
  assert.equal(printed.trim(), fingerprint(readFileSync(publicKeyPath, 'utf8')));
  console.log('ok  riegel fingerprint = reference fingerprint');

  const encrypt = (length) => {
    const plainPath = join(directory, `${length}.bin`);
    const sealedPath = join(directory, `${length}.riegel`);
    writeFileSync(plainPath, patternPlaintext(length));
    execFileSync(riegel, ['encrypt', publicKeyPath, plainPath, sealedPath], { stdio: 'ignore' });
    return readFileSync(sealedPath);
  };

  for (const length of [0, 1, 65535, 65536, 65537, 131072, 200000]) {
    assert.deepEqual(decrypt(secretKey, encrypt(length)), patternPlaintext(length));
    console.log(`ok  riegel encrypt -> reference decrypt, ${length} bytes`);
  }

  const twoChunks = encrypt(70000);
  const withoutLastChunk = twoChunks.subarray(0, HEADER_LEN + COMMITMENT_LEN + SEALED_CHUNK_LEN);
  assert.throws(() => decrypt(secretKey, withoutLastChunk), /decryption failed/);
  console.log('ok  reference refuses a container without its last chunk');

  const modified = Buffer.from(twoChunks);
  modified[modified.length - 1] ^= 1;
  assert.throws(() => decrypt(secretKey, modified), /decryption failed/);
  console.log('ok  reference refuses a modified container');

  const otherCommitment = Buffer.from(twoChunks);
  otherCommitment[HEADER_LEN] ^= 1;
  assert.throws(() => decrypt(secretKey, otherCommitment), /decryption failed/);
  console.log('ok  reference refuses a changed key commitment');
} finally {
  rmSync(directory, { recursive: true, force: true });
}
