import { performance } from 'node:perf_hooks';

const PASSWORD_WORK_WINDOW_MS = 60_000;
const PASSWORD_WORK_MAX_STARTS = 10;
const PASSWORD_WORK_MAX_ACTIVE_SOURCES = 512;

export type PasswordWorkNow = () => number;

export interface StartedPasswordWork {
  readonly kind: 'started';
  release(): void;
}

export interface PasswordWorkRateLimited {
  readonly kind: 'rate_limited';
  readonly retryAfterSeconds: number;
}

export interface PasswordWorkBusy {
  readonly kind: 'busy';
  readonly retryAfterSeconds: 1;
}

export interface PasswordWorkUnavailable {
  readonly kind: 'unavailable';
  readonly retryAfterSeconds: 60;
}

export type PasswordWorkRejection =
  PasswordWorkRateLimited | PasswordWorkBusy | PasswordWorkUnavailable;

export type PasswordWorkAdmission = StartedPasswordWork | PasswordWorkRejection;

export class PasswordWorkLimiter {
  // Active source entries are never evicted because eviction would reset their quota.
  private readonly startedAtBySource = new Map<string, number[]>();
  private passwordWorkInProgress = false;

  public constructor(private readonly now: PasswordWorkNow = () => performance.now()) {}

  public tryStart(sourceKey: string): PasswordWorkAdmission {
    const now = this.now();
    this.removeExpiredStarts(now);

    const starts = this.startedAtBySource.get(sourceKey);
    if (starts !== undefined && starts.length >= PASSWORD_WORK_MAX_STARTS) {
      const oldestStart = starts[0];
      if (oldestStart === undefined) throw new Error('Password work starts must not be empty.');
      return {
        kind: 'rate_limited',
        retryAfterSeconds: secondsUntilExpiry(oldestStart, now),
      };
    }
    if (starts === undefined && this.startedAtBySource.size >= PASSWORD_WORK_MAX_ACTIVE_SOURCES) {
      return { kind: 'unavailable', retryAfterSeconds: 60 };
    }
    if (this.passwordWorkInProgress) return { kind: 'busy', retryAfterSeconds: 1 };

    const admittedStarts = starts ?? [];
    admittedStarts.push(now);
    this.startedAtBySource.set(sourceKey, admittedStarts);
    this.passwordWorkInProgress = true;
    let released = false;
    return {
      kind: 'started',
      release: (): void => {
        if (released) return;
        released = true;
        this.passwordWorkInProgress = false;
      },
    };
  }

  private removeExpiredStarts(now: number): void {
    for (const [sourceKey, starts] of this.startedAtBySource) {
      const activeStarts = starts.filter((startedAt) => now - startedAt < PASSWORD_WORK_WINDOW_MS);
      if (activeStarts.length === 0) {
        this.startedAtBySource.delete(sourceKey);
      } else if (activeStarts.length !== starts.length) {
        this.startedAtBySource.set(sourceKey, activeStarts);
      }
    }
  }
}

function secondsUntilExpiry(startedAt: number, now: number): number {
  return Math.max(1, Math.min(60, Math.ceil((startedAt + PASSWORD_WORK_WINDOW_MS - now) / 1000)));
}
