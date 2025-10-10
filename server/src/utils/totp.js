import speakeasy from 'speakeasy';
import qrcode from 'qrcode';

export function generateTOTPSecret(label) {
  const secret = speakeasy.generateSecret({ length: 20, name: `${process.env.TOTP_ISSUER || 'SafeTalk'}:${label}` });
  const otpauth_url = secret.otpauth_url;
  return { base32: secret.base32, otpauth_url };
}

export async function qrCodeDataURL(otpauth_url) {
  return await qrcode.toDataURL(otpauth_url);
}

export function verifyTOTP({ secret, token }) {
  return speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
}