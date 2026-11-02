import { randomUUID } from 'node:crypto';

import { Inject, Injectable } from '@nestjs/common';

import { canonicalizeIdentityEmail } from '#shared/validation/identity-input.validation';
import {
  createOpaqueIdentityToken,
  isOpaqueIdentityToken,
  sha256Hex,
} from '../helpers/auth-secrets';
import { IdentityAuthConfig } from '../config/identity-auth.config';
import { IDENTITY_CLOCK, IdentityClock } from '../contracts/identity-clock.contracts';
import { PasswordWorkLimiter } from '../../credentials/services/password-work-limiter';
import {
  CsrfBootstrapLimiter,
  CsrfBootstrapRateLimited,
  CsrfBootstrapUnavailable,
} from '../helpers/csrf-bootstrap-limiter';
import {
  IDENTITY_TRANSACTION_PORT,
  IdentityTransactionPort,
  IdentityTransactionScope,
} from '../../interfaces/identity.ports';
import { ScryptPasswordHasher } from '../../credentials/services/password-hasher';
import {
  createCsrfBootstrapSourceKey,
  createPasswordWorkSourceKey,
  createThrottleKey,
  ThrottlePurpose,
} from '../helpers/throttle-key';
import { LOGIN_FAILURE_LIMIT, Session } from '../../../domain/identity.types';
import {
  AuthEmailPasswordCommand,
  AuthenticatedCsrfCheck,
  AuthenticatedCsrfCheckInput,
  AuthenticatedIdentity,
  AuthenticatedSessionCheck,
  AuthenticatedSessionContext,
  AuthenticatedSessionResult,
  CsrfBootstrapOutcome,
  CsrfBootstrapRejection,
  CsrfBootstrapResult,
  CsrfBootstrapInput,
  IdentityAuthenticationFailure,
  IdentityAccessFactsUnavailableFailure,
  InitialPreAuthCheck,
  LoginResult,
  PreAuthContext,
  PreAuthCsrfCheckInput,
  RegistrationResult,
} from '../contracts/identity-authentication.contracts';
import {
  assertCurrentPreAuthSession,
  AUTH_ABSOLUTE_LIFETIME_MS,
  AUTH_IDLE_LIFETIME_MS,
  isActiveSession,
  minDate,
  plusMilliseconds,
  PRE_AUTH_LIFETIME_MS,
  THROTTLE_WINDOW_MS,
  toDurableThrottleRejection,
} from '../policies/identity-session.policy';
import {
  consumeCurrentPreAuth,
  createAuthenticatedSession,
  verifyCurrentPreAuth,
} from '../helpers/identity-session-transition.helper';
import type { Nullable, Optional } from '#shared/types/absence.types';

/** Coordinates identity session transitions through the transaction port. */
@Injectable()
export class IdentityAuthenticationService {
  private readonly passwordWorkLimiter = new PasswordWorkLimiter();
  private readonly csrfBootstrapLimiter = new CsrfBootstrapLimiter();

  public constructor(
    @Inject(IDENTITY_TRANSACTION_PORT) private readonly transactions: IdentityTransactionPort,
    @Inject(IDENTITY_CLOCK) private readonly clock: IdentityClock,
    private readonly config: IdentityAuthConfig,
    private readonly passwordHasher: ScryptPasswordHasher,
  ) {}

  /** Creates or rotates the CSRF material without accepting an arbitrary origin. */
  public async bootstrapCsrf(input: CsrfBootstrapInput): Promise<CsrfBootstrapOutcome> {
    const { cookieValue, origin, remoteAddress } = input;
    if (origin !== undefined && !this.config.corsAllowedOrigins.includes(origin)) {
      return { kind: 'forbidden' };
    }
    if (cookieValue === undefined) return this.createPreAuthSession(remoteAddress);
    if (!isOpaqueIdentityToken(cookieValue)) return { kind: 'clear_and_unauthorized' };

    const tokenHash = sha256Hex(cookieValue);
    const session = await this.transactions.run({
      execute: async (scope) => scope.sessions.findByTokenHash(tokenHash),
    });
    if (session === null) return { kind: 'clear_and_unauthorized' };
    if (session.state === 'authenticated')
      return this.rotateAuthenticatedCsrf(cookieValue, tokenHash);
    const now = this.clock.now();
    if (!isActiveSession(session, now)) return { kind: 'clear_and_unauthorized' };

    const csrfToken = createOpaqueIdentityToken();
    const rotated = await this.transactions.run({
      execute: async (scope) =>
        scope.sessions.rotateActivePreAuthCsrf({
          id: session.id,
          tokenHash,
          csrfTokenHash: sha256Hex(csrfToken),
          now,
        }),
    });
    if (rotated.affectedRows === 0) return { kind: 'clear_and_unauthorized' };
    return { csrfToken, sessionToken: cookieValue };
  }

  /** Reads current identity facts without extending session lifetime. */
  public async getAuthenticatedIdentity(
    cookieValue: Optional<string>,
  ): Promise<Nullable<AuthenticatedIdentity>> {
    if (cookieValue === undefined || !isOpaqueIdentityToken(cookieValue)) return null;
    const tokenHash = sha256Hex(cookieValue);
    return this.transactions.run({
      execute: async (scope) => {
        const locked = await scope.sessions.findLockedAuthenticatedByTokenHash(tokenHash);
        if (locked === null) return null;
        const current = await scope.sessions.findCurrentLockedAuthenticated(locked.id, tokenHash);
        if (current === null || current.userId === null) return null;
        const user = await scope.users.findById(current.userId);
        if (user === null) return null;
        const access = await scope.accessCapabilities.findActiveProjectionForUser(user.id);
        if (access.kind === 'unavailable') throw new IdentityAccessFactsUnavailableFailure();
        return {
          id: user.id,
          email: user.normalizedEmail,
          capabilities: access.projection.capabilities,
        };
      },
    });
  }

  /** Validates an authenticated mutation context under the current session lock. */
  public async checkAuthenticatedCsrf(
    input: AuthenticatedCsrfCheckInput,
  ): Promise<AuthenticatedSessionCheck> {
    // Authenticate the origin and opaque session before entering the locked CSRF comparison.
    const { cookieValue, csrfToken, origin } = input;
    if (origin === undefined || !this.config.corsAllowedOrigins.includes(origin)) {
      return { kind: 'forbidden' };
    }
    if (cookieValue === undefined || !isOpaqueIdentityToken(cookieValue)) {
      return { kind: 'clear_and_unauthorized' };
    }
    const tokenHash = sha256Hex(cookieValue);
    return this.transactions.run({
      execute: async (scope) => {
        const locked = await scope.sessions.findLockedAuthenticatedByTokenHash(tokenHash);
        if (locked === null) return { kind: 'clear_and_unauthorized' };
        const current = await scope.sessions.findCurrentLockedAuthenticated(locked.id, tokenHash);
        if (current === null) return { kind: 'clear_and_unauthorized' };
        if (csrfToken === undefined || sha256Hex(csrfToken) !== current.csrfTokenHash) {
          return { kind: 'csrf_invalid' };
        }
        return {
          kind: 'accepted',
          context: {
            sessionId: current.id,
            tokenHash,
            csrfTokenHash: current.csrfTokenHash,
          },
        };
      },
    });
  }

  /** Revokes only the still-current authenticated session represented by the guard context. */
  public async logout(context: AuthenticatedSessionContext): Promise<AuthenticatedSessionCheck> {
    return this.transactions.run({
      execute: async (scope) => {
        const locked = await scope.sessions.findLockedAuthenticatedByTokenHash(context.tokenHash);
        if (locked === null || locked.id !== context.sessionId) {
          return { kind: 'clear_and_unauthorized' };
        }
        const current = await scope.sessions.findCurrentLockedAuthenticated(
          locked.id,
          context.tokenHash,
        );
        if (current === null || current.id !== context.sessionId) {
          return { kind: 'clear_and_unauthorized' };
        }
        if (current.csrfTokenHash !== context.csrfTokenHash) return { kind: 'csrf_invalid' };
        const revoked = await scope.sessions.revokeCurrentAuthenticatedSession({
          id: context.sessionId,
          tokenHash: context.tokenHash,
          csrfTokenHash: context.csrfTokenHash,
        });
        return revoked.affectedRows === 1
          ? { kind: 'accepted', context }
          : { kind: 'clear_and_unauthorized' };
      },
    });
  }

  /** Validates pre-auth CSRF material before a credential transition. */
  public async checkInitialPreAuth(input: PreAuthCsrfCheckInput): Promise<InitialPreAuthCheck> {
    const { cookieValue, csrfToken, origin } = input;
    if (origin === undefined || !this.config.corsAllowedOrigins.includes(origin)) {
      return { kind: 'forbidden' };
    }
    if (cookieValue === undefined || !isOpaqueIdentityToken(cookieValue)) {
      return { kind: 'clear_and_unauthorized' };
    }
    const tokenHash = sha256Hex(cookieValue);
    const session = await this.transactions.run({
      execute: async (scope) => scope.sessions.findByTokenHash(tokenHash),
    });
    const now = this.clock.now();
    if (session === null || !isActiveSession(session, now))
      return { kind: 'clear_and_unauthorized' };
    if (session.state === 'authenticated') return { kind: 'forbidden' };
    if (csrfToken === undefined || sha256Hex(csrfToken) !== session.csrfTokenHash) {
      return { kind: 'csrf_invalid' };
    }
    return {
      kind: 'accepted',
      context: { sessionId: session.id, tokenHash, csrfTokenHash: session.csrfTokenHash },
    };
  }

  public async register(
    preAuth: PreAuthContext,
    command: AuthEmailPasswordCommand,
  ): Promise<RegistrationResult> {
    const canonicalEmail = canonicalizeIdentityEmail(command.email);
    const throttleKey = this.getThrottleKey('registration', canonicalEmail, command.remoteAddress);
    const passwordWorkSourceKey = this.getPasswordWorkSourceKey(command.remoteAddress);
    return this.transactions.run({
      execute: async (scope) => {
        const lockedSession = await scope.sessions.findLockedById(preAuth.sessionId);
        const now = this.clock.now();
        assertCurrentPreAuthSession(lockedSession, preAuth, now);
        const admitted = await scope.registrationThrottles.consumeAttempt({
          keyHash: throttleKey,
          now,
          expiresAt: plusMilliseconds(now, THROTTLE_WINDOW_MS),
        });
        if (admitted.kind !== 'admitted') {
          return admitted.kind === 'durable_rate_limited'
            ? toDurableThrottleRejection(admitted.expiresAt, now)
            : admitted;
        }

        const passwordWork = this.passwordWorkLimiter.tryStart(passwordWorkSourceKey);
        if (passwordWork.kind !== 'started') return passwordWork;
        let passwordHash: string;
        try {
          passwordHash = await this.passwordHasher.hash(command.password);
        } finally {
          passwordWork.release();
        }
        const inserted = await scope.users.insertIfAbsent({
          id: randomUUID(),
          normalizedEmail: canonicalEmail,
          passwordHash,
          createdAt: now,
          updatedAt: now,
        });
        if (!inserted) return 'duplicate';
        await consumeCurrentPreAuth(scope, preAuth);
        return 'registered';
      },
    });
  }

  public async login(
    preAuth: PreAuthContext,
    command: AuthEmailPasswordCommand,
  ): Promise<LoginResult | AuthenticatedSessionResult> {
    const canonicalEmail = canonicalizeIdentityEmail(command.email);
    const throttleKey = this.getThrottleKey('login', canonicalEmail, command.remoteAddress);
    const passwordWorkSourceKey = this.getPasswordWorkSourceKey(command.remoteAddress);
    return this.transactions.run({
      execute: async (scope) => {
        const lockedSession = await scope.sessions.findLockedById(preAuth.sessionId);
        const now = this.clock.now();
        assertCurrentPreAuthSession(lockedSession, preAuth, now);
        const throttle = await scope.loginThrottles.acquireForLogin({
          keyHash: throttleKey,
          now,
          expiresAt: plusMilliseconds(now, THROTTLE_WINDOW_MS),
        });
        if ('kind' in throttle) return throttle;
        if (throttle.failureCount >= LOGIN_FAILURE_LIMIT) {
          return toDurableThrottleRejection(throttle.expiresAt, now);
        }
        const user = await scope.users.findByNormalizedEmail(canonicalEmail);
        const passwordWork = this.passwordWorkLimiter.tryStart(passwordWorkSourceKey);
        if (passwordWork.kind !== 'started') return passwordWork;
        let verified: boolean;
        try {
          verified =
            user === null
              ? (await this.passwordHasher.verifyDummy(command.password), false)
              : await this.passwordHasher.verify(command.password, user.passwordHash);
        } finally {
          passwordWork.release();
        }
        if (!verified || user === null) {
          const failure = await scope.loginThrottles.consumeFailure(throttleKey, now);
          if (failure.kind === 'durable_rate_limited') {
            return toDurableThrottleRejection(failure.expiresAt, now);
          }
          if (failure.kind !== 'admitted') return failure;
          await verifyCurrentPreAuth(scope, preAuth);
          return 'invalid_credentials';
        }

        await scope.loginThrottles.resetFailures(throttleKey, now);
        await consumeCurrentPreAuth(scope, preAuth);
        const sessionToken = createOpaqueIdentityToken();
        await scope.sessions.insert(createAuthenticatedSession(user.id, sessionToken, now));
        return { sessionToken };
      },
    });
  }

  private async createPreAuthSession(
    remoteAddress: Optional<string>,
  ): Promise<CsrfBootstrapResult | CsrfBootstrapRejection> {
    const sourceKey = createCsrfBootstrapSourceKey(this.config, remoteAddress);
    if (sourceKey === null) throw new IdentityAuthenticationFailure('forbidden');
    const localAdmission = this.csrfBootstrapLimiter.tryStart(sourceKey);
    if (localAdmission.kind !== 'started') return localAdmission;

    const now = this.clock.now();
    const sessionToken = createOpaqueIdentityToken();
    const csrfToken = createOpaqueIdentityToken();
    const admission = await this.transactions.run({
      execute: async (scope) =>
        scope.sessions.admitBootstrapPreAuthSession({
          now,
          session: {
            id: randomUUID(),
            userId: null,
            tokenHash: sha256Hex(sessionToken),
            csrfTokenHash: sha256Hex(csrfToken),
            state: 'pre_auth',
            createdAt: now,
            lastSeenAt: now,
            absoluteExpiresAt: plusMilliseconds(now, PRE_AUTH_LIFETIME_MS),
            idleExpiresAt: plusMilliseconds(now, PRE_AUTH_LIFETIME_MS),
            revokedAt: null,
          },
        }),
    });
    if (admission.kind === 'busy') return { kind: 'busy', retryAfterSeconds: 1 };
    if (admission.kind === 'capacity_unavailable') {
      return { kind: 'capacity_unavailable', retryAfterSeconds: 60 };
    }
    return { csrfToken, sessionToken };
  }

  private async rotateAuthenticatedCsrf(
    sessionToken: string,
    tokenHash: string,
  ): Promise<AuthenticatedCsrfCheck> {
    return this.transactions.run({
      execute: async (scope) => {
        const locked = await scope.sessions.findLockedAuthenticatedByTokenHash(tokenHash);
        if (locked === null) return { kind: 'clear_and_unauthorized' };
        const now = this.clock.now();
        if (now < locked.lastSeenAt || now >= locked.absoluteExpiresAt) {
          return { kind: 'clear_and_unauthorized' };
        }
        const csrfToken = createOpaqueIdentityToken();
        const rotated = await scope.sessions.rotateCurrentAuthenticatedCsrf({
          id: locked.id,
          tokenHash,
          csrfTokenHash: sha256Hex(csrfToken),
          lastSeenAt: now,
          idleExpiresAt: minDate(
            plusMilliseconds(now, AUTH_IDLE_LIFETIME_MS),
            locked.absoluteExpiresAt,
          ),
        });
        return rotated.affectedRows === 1
          ? { kind: 'authenticated_csrf', csrfToken, sessionToken }
          : { kind: 'clear_and_unauthorized' };
      },
    });
  }

  private getThrottleKey(
    purpose: ThrottlePurpose,
    canonicalEmail: string,
    remoteAddress: Optional<string>,
  ): string {
    const key = createThrottleKey(this.config, purpose, canonicalEmail, remoteAddress);
    if (key === null) throw new IdentityAuthenticationFailure('forbidden');
    return key;
  }

  private getPasswordWorkSourceKey(remoteAddress: Optional<string>): string {
    const key = createPasswordWorkSourceKey(this.config, remoteAddress);
    if (key === null) throw new IdentityAuthenticationFailure('forbidden');
    return key;
  }
}
