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

export interface ConsumePreAuthSessionInput {
  readonly id: string;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
  readonly now: Date;
}

export interface SessionTransitionResult {
  readonly affectedRows: AffectedRows;
}

export interface ThrottleWindowInput {
  readonly keyHash: string;
  readonly now: Date;
  readonly expiresAt: Date;
}

export interface ThrottleAdmissionResult {
  readonly admitted: boolean;
}

export interface RegistrationThrottleLookup {
  readonly keyHash: string;
  readonly windowStartedAt: Date;
}

export interface LoginThrottleLookup {
  readonly keyHash: string;
  readonly windowStartedAt: Date;
}
