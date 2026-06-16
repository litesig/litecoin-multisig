// AES-256-GCM with a PBKDF2-derived key (OWASP-minimum 310k iterations,
// SHA-256). Used for the local KeyStore and the server-synced wallet config
// blob. Runs on window.crypto.subtle in browsers and Node's webcrypto in tests.
const enc = new TextEncoder();
const dec = new TextDecoder();

const ITERATIONS = 310000;
const IV_BYTES = 12;

async function deriveKey(passphrase, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// → base64(iv ‖ ciphertext ‖ gcm-tag)
export async function encryptString(passphrase, salt, plaintext) {
  const key = await deriveKey(passphrase, salt);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext))
  );
  const out = new Uint8Array(iv.length + cipher.length);
  out.set(iv);
  out.set(cipher, iv.length);
  let bin = '';
  for (const b of out) bin += String.fromCharCode(b);
  return btoa(bin);
}

// Rejects (GCM auth failure) on a wrong passphrase or tampered payload.
export async function decryptString(passphrase, salt, payloadB64) {
  const raw = Uint8Array.from(atob(payloadB64), (c) => c.charCodeAt(0));
  const key = await deriveKey(passphrase, salt);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: raw.slice(0, IV_BYTES) },
    key,
    raw.slice(IV_BYTES)
  );
  return dec.decode(plain);
}
