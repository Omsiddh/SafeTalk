// Browser-side crypto helpers using Web Crypto API

function str2ab(str) {
  return new TextEncoder().encode(str);
}

function ab2b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b642ab(b64) {
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

export async function generateRSAKeyPair() {
  return await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportPublicKeyToBase64SPKI(publicKey) {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  return ab2b64(spki);
}

export async function exportPrivateKeyPkcs8(privateKey) {
  return await crypto.subtle.exportKey('pkcs8', privateKey);
}

export async function importPublicKeyFromBase64(spkiB64) {
  const spki = b642ab(spkiB64);
  return await crypto.subtle.importKey(
    'spki',
    spki,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

export async function importPrivateKeyPkcs8(pkcs8Buf) {
  return await crypto.subtle.importKey(
    'pkcs8',
    pkcs8Buf,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}

export async function deriveAESKeyFromPassword(password, username) {
  const salt = str2ab(username);
  const keyMaterial = await crypto.subtle.importKey('raw', str2ab(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export function randomIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}

export async function encryptPrivateKey(privateKey, aesKey) {
  const pkcs8 = await exportPrivateKeyPkcs8(privateKey);
  const iv = randomIV();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, pkcs8);
  return { ciphertext: ab2b64(ct), iv: ab2b64(iv) };
}

export async function decryptPrivateKey(encryptedB64, ivB64, aesKey) {
  const ct = b642ab(encryptedB64);
  const iv = new Uint8Array(b642ab(ivB64));
  const pkcs8 = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return await importPrivateKeyPkcs8(pkcs8);
}

export async function generateAESKey() {
  return await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function encryptMessage(plaintext, aesKey) {
  const iv = randomIV();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, str2ab(plaintext));
  return { ciphertext: ab2b64(ct), iv: ab2b64(iv) };
}

export async function decryptMessage(ciphertextB64, ivB64, aesKey) {
  const ct = b642ab(ciphertextB64);
  const iv = new Uint8Array(b642ab(ivB64));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return new TextDecoder().decode(pt);
}

export async function wrapAESKeyWithRSA(aesKey, publicKey) {
  const raw = await crypto.subtle.exportKey('raw', aesKey);
  const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, raw);
  return ab2b64(wrapped);
}

export async function unwrapAESKeyWithRSA(wrappedB64, privateKey) {
  const wrapped = b642ab(wrappedB64);
  const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, wrapped);
  return await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
}