import { PasswordWorkLimiter } from '../../../src/modules/identity/application/password-work-limiter';

describe('Password work limiter', () => {
  it('shares ten started-password-work admissions by source and rounds the remaining window', () => {
    let now = 0;
    const limiter = new PasswordWorkLimiter(() => now);

    for (let attempt = 0; attempt < 10; attempt += 1) {
      const admission = limiter.tryStart('source-a');
      expect(admission.kind).toBe('started');
      if (admission.kind === 'started') admission.release();
    }

    now = 59_001;
    expect(limiter.tryStart('source-a')).toEqual({
      kind: 'rate_limited',
      retryAfterSeconds: 1,
    });

    now = 60_000;
    const renewed = limiter.tryStart('source-a');
    expect(renewed.kind).toBe('started');
    if (renewed.kind === 'started') renewed.release();
  });

  it('does not debit a source when the one KDF slot is busy and releases its slot exactly once', () => {
    const limiter = new PasswordWorkLimiter(() => 0);
    const first = limiter.tryStart('source-a');
    expect(first.kind).toBe('started');
    expect(limiter.tryStart('source-b')).toEqual({ kind: 'busy', retryAfterSeconds: 1 });

    if (first.kind !== 'started') throw new Error('Expected first KDF admission.');
    first.release();
    first.release();

    for (let attempt = 0; attempt < 10; attempt += 1) {
      const admission = limiter.tryStart('source-b');
      expect(admission.kind).toBe('started');
      if (admission.kind === 'started') admission.release();
    }
    expect(limiter.tryStart('source-b')).toEqual({
      kind: 'rate_limited',
      retryAfterSeconds: 60,
    });
  });

  it('sweeps every expired source before full-map rejection without evicting active sources', () => {
    let now = 0;
    const limiter = new PasswordWorkLimiter(() => now);

    for (let index = 0; index < 512; index += 1) {
      const admission = limiter.tryStart(`source-${index}`);
      expect(admission.kind).toBe('started');
      if (admission.kind === 'started') admission.release();
    }
    expect(limiter.tryStart('new-source')).toEqual({ kind: 'unavailable', retryAfterSeconds: 60 });

    const retained = limiter.tryStart('source-0');
    expect(retained.kind).toBe('started');
    if (retained.kind === 'started') retained.release();

    now = 60_000;
    const afterExpiry = limiter.tryStart('new-source');
    expect(afterExpiry.kind).toBe('started');
    if (afterExpiry.kind === 'started') afterExpiry.release();
  });
});
