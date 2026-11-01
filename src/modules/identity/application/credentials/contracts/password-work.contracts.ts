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
  readonly retryAfterSeconds: number;
}

export interface PasswordWorkUnavailable {
  readonly kind: 'unavailable';
  readonly retryAfterSeconds: number;
}

export type PasswordWorkRejection =
  PasswordWorkRateLimited | PasswordWorkBusy | PasswordWorkUnavailable;

export type PasswordWorkAdmission = StartedPasswordWork | PasswordWorkRejection;
