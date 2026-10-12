import { randomBytes } from 'node:crypto';

import { IdentityAuthConfig } from '../../../src/modules/identity/application/identity-auth.config';
import { ScryptPasswordHasher } from '../../../src/modules/identity/application/password-hasher';
import { createThrottleKey } from '../../../src/modules/identity/application/throttle-key';

const HMAC_SECRET = randomBytes(32).toString('base64url');

describe('Identity authentication primitives', () => {
  it('creates and verifies the approved versioned scrypt record', async () => {
    const hasher = new ScryptPasswordHasher();
    const password = 'literal Unicode password ١٢٣';

    const record = await hasher.hash(password);
    const parts = record.split('$');

    expect(parts).toHaveLength(7);
    expect(parts.slice(0, 5)).toEqual(['scrypt', 'v1', '131072', '8', '1']);
    expect(Buffer.from(parts[5] ?? '', 'base64url')).toHaveLength(16);
    expect(Buffer.from(parts[6] ?? '', 'base64url')).toHaveLength(64);
    await expect(hasher.verify(password, record)).resolves.toBe(true);
    await expect(hasher.verify(`${password}!`, record)).resolves.toBe(false);
    await expect(hasher.verify(password, 'scrypt$v1$32768$8$1$bad$bad')).resolves.toBe(false);
  });

  it('derives lowercase hexadecimal, purpose-separated trusted-address throttle keys', () => {
    const config = IdentityAuthConfig.from({
      NODE_ENV: 'test',
      IDENTITY_THROTTLE_HMAC_SECRET: HMAC_SECRET,
    });

    const registration = createThrottleKey(
      config,
      'registration',
      'student@example.test',
      '::ffff:127.0.0.1',
    );
    const registrationRepeated = createThrottleKey(
      config,
      'registration',
      'student@example.test',
      '127.0.0.1',
    );
    const login = createThrottleKey(config, 'login', 'student@example.test', '127.0.0.1');

    expect(registration).toMatch(/^[a-f0-9]{64}$/);
    expect(registrationRepeated).toBe(registration);
    expect(login).toMatch(/^[a-f0-9]{64}$/);
    expect(login).not.toBe(registration);
    expect(createThrottleKey(config, 'login', 'student@example.test', undefined)).toBeNull();
    expect(createThrottleKey(config, 'login', 'student@example.test', 'not-an-ip')).toBeNull();
  });
});
