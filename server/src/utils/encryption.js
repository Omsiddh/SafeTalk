// Server-side encryption utilities are minimal because encryption happens on the client.
// We keep helpers to validate public key format (base64-encoded SPKI) to avoid storing junk.

const BASE64_RE = /^[A-Za-z0-9+/=]+$/;

export function isValidPublicKey(spkiBase64) {
  if (typeof spkiBase64 !== 'string') return false;
  if (!BASE64_RE.test(spkiBase64)) return false;
  // Basic length sanity check for SPKI DER (should be at least a few hundred bytes after base64 decode)
  return spkiBase64.length > 100;
}