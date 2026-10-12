import { ScryptPasswordHasher } from './password-hasher';

describe('ScryptPasswordHasher', () => {
  it('stores and verifies the approved versioned scrypt record', async () => {
    const hasher = new ScryptPasswordHasher();
    const password = 'correct horse battery staple';
    const record = await hasher.hash(password);

    expect(record).toMatch(/^scrypt\$v1\$131072\$8\$1\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{86}$/);
    await expect(hasher.verify(password, record)).resolves.toBe(true);
    await expect(hasher.verify('different password', record)).resolves.toBe(false);
  });
});
