export type SessionState = 'pre_auth' | 'authenticated' | 'revoked';
export type AffectedRows = 0 | 1;
export const LOGIN_FAILURE_LIMIT = 5;

export interface User {
  readonly id: string;
  readonly normalizedEmail: string;
  readonly passwordHash: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface Session {
  readonly id: string;
  readonly userId: string | null;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
  readonly state: SessionState;
  readonly createdAt: Date;
  readonly lastSeenAt: Date;
  readonly absoluteExpiresAt: Date;
  readonly idleExpiresAt: Date;
  readonly revokedAt: Date | null;
}

export interface RegistrationThrottle {
  readonly id: string;
  readonly keyHash: string;
  readonly windowStartedAt: Date;
  readonly expiresAt: Date;
  readonly attemptCount: number;
}

export interface LoginThrottle {
  readonly id: string;
  readonly keyHash: string;
  readonly windowStartedAt: Date;
  readonly expiresAt: Date;
  readonly failureCount: number;
}

export interface RevokeActiveSessionInput {
  readonly id: string;
  readonly tokenHash: string;
  readonly now: Date;
}

export interface RotatePreAuthCsrfInput {
  readonly id: string;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
  readonly now: Date;
}

export interface RotateAuthenticatedCsrfInput {
  readonly id: string;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
  readonly lastSeenAt: Date;
  readonly idleExpiresAt: Date;
}

export interface RevokeAuthenticatedSessionInput {
  readonly id: string;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
}

export interface ConsumePreAuthSessionInput {
  readonly id: string;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
}

export interface VerifyCurrentPreAuthInput {
  readonly id: string;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
}

export interface SessionTransitionResult {
  readonly affectedRows: AffectedRows;
}

export interface BootstrapPreAuthSessionInput {
  readonly session: Session;
  readonly now: Date;
}

export type BootstrapPreAuthSessionAdmission =
  | { readonly kind: 'created' }
  | { readonly kind: 'busy' }
  | { readonly kind: 'capacity_unavailable' };

export interface ThrottleWindowInput {
  readonly keyHash: string;
  readonly now: Date;
  readonly expiresAt: Date;
}

export type ThrottleAdmissionResult =
  { readonly kind: 'admitted' } | DurableThrottleWindowRejection | ThrottleAdmissionRejection;

export interface DurableThrottleWindowRejection {
  readonly kind: 'durable_rate_limited';
  readonly expiresAt: Date;
}

export interface DurableThrottleRejection {
  readonly kind: 'durable_rate_limited';
  readonly retryAfterSeconds: number;
}

export type ThrottleAdmissionRejection =
  | { readonly kind: 'throttle_busy'; readonly retryAfterSeconds: 1 }
  | { readonly kind: 'throttle_capacity_unavailable'; readonly retryAfterSeconds: 60 };

export interface RegistrationThrottleLookup {
  readonly keyHash: string;
  readonly windowStartedAt: Date;
}

export interface LoginThrottleLookup {
  readonly keyHash: string;
  readonly windowStartedAt: Date;
}
