import { Session, DurableThrottleRejection } from '../../../domain/identity.types';
import { PreAuthContext } from '../contracts/identity-authentication.contracts';
import { IdentityAuthenticationFailure } from '../contracts/identity-authentication.contracts';
import type { Nullable } from '#shared/types/absence.types';

export const PRE_AUTH_LIFETIME_MS = 10 * 60 * 1000;
export const AUTH_IDLE_LIFETIME_MS = 8 * 60 * 60 * 1000;
export const AUTH_ABSOLUTE_LIFETIME_MS = 24 * 60 * 60 * 1000;
export const THROTTLE_WINDOW_MS = 15 * 60 * 1000;

export function isActiveSession(session: Session, now: Date): boolean {
  return (
    session.state !== 'revoked' &&
    session.revokedAt === null &&
    session.absoluteExpiresAt > now &&
    session.idleExpiresAt > now
  );
}

export function assertCurrentPreAuthSession(
  session: Nullable<Session>,
  preAuth: PreAuthContext,
  now: Date,
): void {
  if (
    session === null ||
    session.tokenHash !== preAuth.tokenHash ||
    session.state !== 'pre_auth' ||
    session.revokedAt !== null ||
    session.absoluteExpiresAt <= now ||
    session.idleExpiresAt <= now
  ) {
    throw new IdentityAuthenticationFailure('unauthorized');
  }
  if (session.csrfTokenHash !== preAuth.csrfTokenHash)
    throw new IdentityAuthenticationFailure('csrf_invalid');
}

export function plusMilliseconds(value: Date, milliseconds: number): Date {
  return new Date(value.getTime() + milliseconds);
}

export function minDate(first: Date, second: Date): Date {
  return first <= second ? first : second;
}

export function toDurableThrottleRejection(expiresAt: Date, now: Date): DurableThrottleRejection {
  return {
    kind: 'durable_rate_limited',
    retryAfterSeconds: Math.max(1, Math.ceil((expiresAt.getTime() - now.getTime()) / 1000)),
  };
}
