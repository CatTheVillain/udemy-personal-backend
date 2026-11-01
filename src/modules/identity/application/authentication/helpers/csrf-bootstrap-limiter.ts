import { performance } from 'node:perf_hooks';

const CSRF_BOOTSTRAP_WINDOW_MS = 60_000;
const CSRF_BOOTSTRAP_MAX_ATTEMPTS = 10;
const CSRF_BOOTSTRAP_MAX_ACTIVE_SOURCES = 512;

export type CsrfBootstrapNow = () => number;

export interface CsrfBootstrapStarted {
  readonly kind: 'started';
}

export interface CsrfBootstrapRateLimited {
  readonly kind: 'rate_limited';
  readonly retryAfterSeconds: number;
}

export interface CsrfBootstrapUnavailable {
  readonly kind: 'unavailable';
  readonly retryAfterSeconds: 60;
}

export type CsrfBootstrapAdmission =
  CsrfBootstrapStarted | CsrfBootstrapRateLimited | CsrfBootstrapUnavailable;

export class CsrfBootstrapLimiter {
  // Active source entries are never evicted because eviction would reset their quota.
  private readonly attemptedAtBySource = new Map<string, number[]>();

  public constructor(private readonly now: CsrfBootstrapNow = () => performance.now()) {}

  public tryStart(sourceKey: string): CsrfBootstrapAdmission {
    const now = this.now();
    this.removeExpiredAttempts(now);

    const attempts = this.attemptedAtBySource.get(sourceKey);
    if (attempts !== undefined && attempts.length >= CSRF_BOOTSTRAP_MAX_ATTEMPTS) {
      const oldestAttempt = attempts[0];
      if (oldestAttempt === undefined)
        throw new Error('CSRF bootstrap attempts must not be empty.');
      return {
        kind: 'rate_limited',
        retryAfterSeconds: secondsUntilExpiry(oldestAttempt, now),
      };
    }
    if (
      attempts === undefined &&
      this.attemptedAtBySource.size >= CSRF_BOOTSTRAP_MAX_ACTIVE_SOURCES
    ) {
      return { kind: 'unavailable', retryAfterSeconds: 60 };
    }

    const admittedAttempts = attempts ?? [];
    admittedAttempts.push(now);
    this.attemptedAtBySource.set(sourceKey, admittedAttempts);
    return { kind: 'started' };
  }

  private removeExpiredAttempts(now: number): void {
    for (const [sourceKey, attempts] of this.attemptedAtBySource) {
      const activeAttempts = attempts.filter(
        (attemptedAt) => now - attemptedAt < CSRF_BOOTSTRAP_WINDOW_MS,
      );
      if (activeAttempts.length === 0) {
        this.attemptedAtBySource.delete(sourceKey);
      } else if (activeAttempts.length !== attempts.length) {
        this.attemptedAtBySource.set(sourceKey, activeAttempts);
      }
    }
  }
}

function secondsUntilExpiry(attemptedAt: number, now: number): number {
  return Math.max(
    1,
    Math.min(60, Math.ceil((attemptedAt + CSRF_BOOTSTRAP_WINDOW_MS - now) / 1000)),
  );
}
