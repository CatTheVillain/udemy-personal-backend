import { PasswordWorkLimiter } from '../../../src/modules/identity/application/password-work-limiter';
import { CsrfBootstrapLimiter } from '../../../src/modules/identity/application/csrf-bootstrap-limiter';
import { IdentityAuthConfig } from '../../../src/modules/identity/application/identity-auth.config';
import {
  createCsrfBootstrapSourceKey,
  createPasswordWorkSourceKey,
} from '../../../src/modules/identity/application/throttle-key';

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

describe('CSRF bootstrap limiter', () => {
  it('uses a dedicated HMAC purpose and canonical socket addresses only', () => {
    const config = IdentityAuthConfig.from({
      IDENTITY_THROTTLE_HMAC_SECRET: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    });
    const ipv4 = createCsrfBootstrapSourceKey(config, '127.0.0.1');
    const mappedIpv4 = createCsrfBootstrapSourceKey(config, '::ffff:127.0.0.1');
    const lowerIpv6 = createCsrfBootstrapSourceKey(config, '2001:db8::abcd');
    const upperIpv6 = createCsrfBootstrapSourceKey(config, '2001:DB8::ABCD');

    expect(ipv4).toMatch(/^[a-f0-9]{64}$/);
    expect(mappedIpv4).toBe(ipv4);
    expect(upperIpv6).toBe(lowerIpv6);
    expect(ipv4).not.toBe(createPasswordWorkSourceKey(config, '127.0.0.1'));
    expect(createCsrfBootstrapSourceKey(config, undefined)).toBeNull();
    expect(createCsrfBootstrapSourceKey(config, 'for=203.0.113.7')).toBeNull();
  });
  it('shares ten attempted creations by source and admits only after the rolling window expires', () => {
    let now = 0;
    const limiter = new CsrfBootstrapLimiter(() => now);

    for (let attempt = 0; attempt < 10; attempt += 1) {
      expect(limiter.tryStart('source-a')).toEqual({ kind: 'started' });
    }

    now = 59_001;
    expect(limiter.tryStart('source-a')).toEqual({
      kind: 'rate_limited',
      retryAfterSeconds: 1,
    });

    now = 60_000;
    expect(limiter.tryStart('source-a')).toEqual({ kind: 'started' });
  });

  it('does not evict active sources to admit a new source and sweeps fully expired entries', () => {
    let now = 0;
    const limiter = new CsrfBootstrapLimiter(() => now);

    for (let index = 0; index < 512; index += 1) {
      expect(limiter.tryStart(`source-${index}`)).toEqual({ kind: 'started' });
    }
    expect(limiter.tryStart('new-source')).toEqual({ kind: 'unavailable', retryAfterSeconds: 60 });

    expect(limiter.tryStart('source-0')).toEqual({ kind: 'started' });
    now = 60_000;
    expect(limiter.tryStart('new-source')).toEqual({ kind: 'started' });
  });
});
