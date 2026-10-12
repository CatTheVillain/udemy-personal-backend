import { createHash, randomBytes } from 'node:crypto';

const OPAQUE_TOKEN_BYTES = 32;

export function createOpaqueIdentityToken(): string {
  return randomBytes(OPAQUE_TOKEN_BYTES).toString('base64url');
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function isOpaqueIdentityToken(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value);
}
