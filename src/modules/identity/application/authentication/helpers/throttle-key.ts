import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';

import { IdentityAuthConfig } from '../config/identity-auth.config';
import type { Nullable, Optional } from '#shared/types/absence.types';

export type ThrottlePurpose = 'login' | 'registration';

export function createThrottleKey(
  config: IdentityAuthConfig,
  purpose: ThrottlePurpose,
  canonicalEmail: string,
  remoteAddress: Optional<string>,
): Nullable<string> {
  const trustedAddress = canonicalizeTrustedAddress(remoteAddress);
  if (trustedAddress === null) return null;
  return createHmac('sha256', config.throttleHmacSecret)
    .update(`${purpose}\u0000${canonicalEmail}\u0000${trustedAddress}`, 'utf8')
    .digest('hex');
}

export function createPasswordWorkSourceKey(
  config: IdentityAuthConfig,
  remoteAddress: Optional<string>,
): Nullable<string> {
  const trustedAddress = canonicalizeTrustedAddress(remoteAddress);
  if (trustedAddress === null) return null;
  return createHmac('sha256', config.throttleHmacSecret)
    .update(`password-work-source\u0000${trustedAddress}`, 'utf8')
    .digest('hex');
}

export function createCsrfBootstrapSourceKey(
  config: IdentityAuthConfig,
  remoteAddress: Optional<string>,
): Nullable<string> {
  const trustedAddress = canonicalizeTrustedAddress(remoteAddress);
  if (trustedAddress === null) return null;
  return createHmac('sha256', config.throttleHmacSecret)
    .update(`csrf-bootstrap-source\u0000${trustedAddress}`, 'utf8')
    .digest('hex');
}

function canonicalizeTrustedAddress(value: Optional<string>): Nullable<string> {
  if (value === undefined || isIP(value) === 0) return null;
  if (value.startsWith('::ffff:')) {
    const ipv4 = value.slice('::ffff:'.length);
    return isIP(ipv4) === 4 ? ipv4 : null;
  }
  return value.toLowerCase();
}
