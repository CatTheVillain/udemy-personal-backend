import { randomUUID } from 'node:crypto';

import { IdentityTransactionScope } from '../../interfaces/identity.ports';
import { Session } from '../../../domain/identity.types';
import { PreAuthContext } from '../contracts/identity-authentication.contracts';
import { IdentityAuthenticationFailure } from '../contracts/identity-authentication.contracts';
import { createOpaqueIdentityToken, sha256Hex } from './auth-secrets';
import {
  AUTH_ABSOLUTE_LIFETIME_MS,
  AUTH_IDLE_LIFETIME_MS,
  plusMilliseconds,
} from '../policies/identity-session.policy';

export async function consumeCurrentPreAuth(
  scope: IdentityTransactionScope,
  preAuth: PreAuthContext,
): Promise<void> {
  // The affected-row check keeps consumption bound to the locked pre-auth session.
  const result = await scope.sessions.consumeLockedPreAuth({
    id: preAuth.sessionId,
    tokenHash: preAuth.tokenHash,
    csrfTokenHash: preAuth.csrfTokenHash,
  });
  if (result.affectedRows !== 1) throw new IdentityAuthenticationFailure('unauthorized');
}

export async function verifyCurrentPreAuth(
  scope: IdentityTransactionScope,
  preAuth: PreAuthContext,
): Promise<void> {
  // Credential failures revalidate the same locked pre-auth session before returning.
  const result = await scope.sessions.verifyCurrentLockedPreAuth({
    id: preAuth.sessionId,
    tokenHash: preAuth.tokenHash,
    csrfTokenHash: preAuth.csrfTokenHash,
  });
  if (result.affectedRows !== 1) throw new IdentityAuthenticationFailure('unauthorized');
}

export function createAuthenticatedSession(
  userId: string,
  sessionToken: string,
  now: Date,
): Session {
  const absoluteExpiresAt = plusMilliseconds(now, AUTH_ABSOLUTE_LIFETIME_MS);
  return {
    id: randomUUID(),
    userId,
    tokenHash: sha256Hex(sessionToken),
    csrfTokenHash: sha256Hex(createOpaqueIdentityToken()),
    state: 'authenticated',
    createdAt: now,
    lastSeenAt: now,
    absoluteExpiresAt,
    idleExpiresAt: plusMilliseconds(now, AUTH_IDLE_LIFETIME_MS),
    revokedAt: null,
  };
}
