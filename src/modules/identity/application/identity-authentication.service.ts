import { randomUUID } from 'node:crypto';

import { Inject, Injectable } from '@nestjs/common';

import { canonicalizeIdentityEmail } from '../../../shared/validation/identity-input.validation';
import { createOpaqueIdentityToken, isOpaqueIdentityToken, sha256Hex } from './auth-secrets';
import { IdentityAuthConfig } from './identity-auth.config';
import { IDENTITY_CLOCK, IdentityClock } from './identity-clock';
import { PasswordWorkLimiter, PasswordWorkRejection } from './password-work-limiter';
import {
  CsrfBootstrapLimiter,
  CsrfBootstrapRateLimited,
  CsrfBootstrapUnavailable,
} from './csrf-bootstrap-limiter';
import {
  IDENTITY_TRANSACTION_PORT,
  IdentityTransactionPort,
  IdentityTransactionScope,
} from './ports/identity.ports';
import { ScryptPasswordHasher } from './password-hasher';
import {
  createCsrfBootstrapSourceKey,
  createPasswordWorkSourceKey,
  createThrottleKey,
  ThrottlePurpose,
} from './throttle-key';
import {
  DurableThrottleRejection,
  LOGIN_FAILURE_LIMIT,
  Session,
  ThrottleAdmissionRejection,
} from '../domain/identity.types';

const PRE_AUTH_LIFETIME_MS = 10 * 60 * 1000;
const AUTH_IDLE_LIFETIME_MS = 8 * 60 * 60 * 1000;
const AUTH_ABSOLUTE_LIFETIME_MS = 24 * 60 * 60 * 1000;
const THROTTLE_WINDOW_MS = 15 * 60 * 1000;

export interface AuthEmailPasswordCommand {
  readonly email: string;
  readonly password: string;
  readonly remoteAddress: string | undefined;
}

export interface PreAuthContext {
  readonly sessionId: string;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
}

export interface CsrfBootstrapResult {
  readonly csrfToken: string;
  readonly sessionToken: string;
}

export type CsrfBootstrapRejection =
  | CsrfBootstrapRateLimited
  | CsrfBootstrapUnavailable
  | { readonly kind: 'busy'; readonly retryAfterSeconds: 1 }
  | { readonly kind: 'capacity_unavailable'; readonly retryAfterSeconds: 60 };

export type CsrfBootstrapOutcome =
  CsrfBootstrapResult | InitialPreAuthCheck | CsrfBootstrapRejection;

export interface AuthenticatedSessionResult {
  readonly sessionToken: string;
}

export type RegistrationResult =
  | 'registered'
  | 'duplicate'
  | DurableThrottleRejection
  | PasswordWorkRejection
  | ThrottleAdmissionRejection;
export type LoginResult =
  | 'invalid_credentials'
  | DurableThrottleRejection
  | PasswordWorkRejection
  | ThrottleAdmissionRejection;
export type InitialPreAuthCheck =
  | { readonly kind: 'accepted'; readonly context: PreAuthContext }
  | { readonly kind: 'clear_and_unauthorized' }
  | { readonly kind: 'forbidden' }
  | { readonly kind: 'csrf_invalid' };

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

  public async bootstrapCsrf(
    cookieValue: string | undefined,
    origin: string | undefined,
    remoteAddress: string | undefined,
  ): Promise<CsrfBootstrapOutcome> {
    if (origin !== undefined && !this.config.corsAllowedOrigins.includes(origin)) {
      return { kind: 'forbidden' };
    }
    if (cookieValue === undefined) return this.createPreAuthSession(remoteAddress);
    if (!isOpaqueIdentityToken(cookieValue)) return { kind: 'clear_and_unauthorized' };

    const tokenHash = sha256Hex(cookieValue);
    const session = await this.transactions.run({
      execute: async (scope) => scope.sessions.findByTokenHash(tokenHash),
    });
    const now = this.clock.now();
    if (session === null || !isActive(session, now)) return { kind: 'clear_and_unauthorized' };
    if (session.state === 'authenticated') return { kind: 'forbidden' };

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

  public async checkInitialPreAuth(
    cookieValue: string | undefined,
    csrfToken: string | undefined,
    origin: string | undefined,
  ): Promise<InitialPreAuthCheck> {
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
    if (session === null || !isActive(session, now)) return { kind: 'clear_and_unauthorized' };
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
        assertCurrentPreAuth(lockedSession, preAuth, now);
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
        assertCurrentPreAuth(lockedSession, preAuth, now);
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
    remoteAddress: string | undefined,
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

  private getThrottleKey(
    purpose: ThrottlePurpose,
    canonicalEmail: string,
    remoteAddress: string | undefined,
  ): string {
    const key = createThrottleKey(this.config, purpose, canonicalEmail, remoteAddress);
    if (key === null) throw new IdentityAuthenticationFailure('forbidden');
    return key;
  }

  private getPasswordWorkSourceKey(remoteAddress: string | undefined): string {
    const key = createPasswordWorkSourceKey(this.config, remoteAddress);
    if (key === null) throw new IdentityAuthenticationFailure('forbidden');
    return key;
  }
}

export type IdentityAuthenticationFailureKind = 'csrf_invalid' | 'forbidden' | 'unauthorized';

export class IdentityAuthenticationFailure extends Error {
  public constructor(public readonly kind: IdentityAuthenticationFailureKind) {
    super(kind);
  }
}

function isActive(session: Session, now: Date): boolean {
  return (
    session.state !== 'revoked' &&
    session.revokedAt === null &&
    session.absoluteExpiresAt > now &&
    session.idleExpiresAt > now
  );
}

function assertCurrentPreAuth(session: Session | null, preAuth: PreAuthContext, now: Date): void {
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
  if (session.csrfTokenHash !== preAuth.csrfTokenHash) {
    throw new IdentityAuthenticationFailure('csrf_invalid');
  }
}

async function consumeCurrentPreAuth(
  scope: IdentityTransactionScope,
  preAuth: PreAuthContext,
): Promise<void> {
  const result = await scope.sessions.consumeLockedPreAuth({
    id: preAuth.sessionId,
    tokenHash: preAuth.tokenHash,
    csrfTokenHash: preAuth.csrfTokenHash,
  });
  if (result.affectedRows !== 1) {
    throw new IdentityAuthenticationFailure('unauthorized');
  }
}

async function verifyCurrentPreAuth(
  scope: IdentityTransactionScope,
  preAuth: PreAuthContext,
): Promise<void> {
  const result = await scope.sessions.verifyCurrentLockedPreAuth({
    id: preAuth.sessionId,
    tokenHash: preAuth.tokenHash,
    csrfTokenHash: preAuth.csrfTokenHash,
  });
  if (result.affectedRows !== 1) {
    throw new IdentityAuthenticationFailure('unauthorized');
  }
}

function createAuthenticatedSession(userId: string, sessionToken: string, now: Date): Session {
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

function plusMilliseconds(value: Date, milliseconds: number): Date {
  return new Date(value.getTime() + milliseconds);
}

function toDurableThrottleRejection(expiresAt: Date, now: Date): DurableThrottleRejection {
  return {
    kind: 'durable_rate_limited',
    retryAfterSeconds: Math.max(1, Math.ceil((expiresAt.getTime() - now.getTime()) / 1000)),
  };
}
