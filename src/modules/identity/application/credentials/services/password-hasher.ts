import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

import { parseScryptRecord } from '../helpers/scrypt-password-record.helper';

const SCRYPT_COST = 131_072;
const SCRYPT_BLOCK_SIZE = 8;
const SCRYPT_PARALLELIZATION = 1;
const SCRYPT_SALT_BYTES = 16;
const SCRYPT_KEY_BYTES = 64;
const SCRYPT_MAX_MEMORY = 268_435_456;
const DUMMY_RECORD = `scrypt$v1$${SCRYPT_COST}$${SCRYPT_BLOCK_SIZE}$${SCRYPT_PARALLELIZATION}$AAAAAAAAAAAAAAAAAAAAAA$${Buffer.alloc(SCRYPT_KEY_BYTES).toString('base64url')}`;

export class ScryptPasswordHasher {
  public async hash(password: string): Promise<string> {
    const salt = randomBytes(SCRYPT_SALT_BYTES);
    const derivedKey = await deriveScryptKey(password, salt);
    return [
      'scrypt',
      'v1',
      String(SCRYPT_COST),
      String(SCRYPT_BLOCK_SIZE),
      String(SCRYPT_PARALLELIZATION),
      salt.toString('base64url'),
      derivedKey.toString('base64url'),
    ].join('$');
  }

  public async verify(password: string, record: string): Promise<boolean> {
    const parsed = parseScryptRecord(record);
    if (parsed === null) return false;
    const derivedKey = await deriveScryptKey(password, parsed.salt);
    return timingSafeEqual(derivedKey, parsed.key);
  }

  public async verifyDummy(password: string): Promise<void> {
    await this.verify(password, DUMMY_RECORD);
  }
}

function deriveScryptKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      password,
      salt,
      SCRYPT_KEY_BYTES,
      {
        N: SCRYPT_COST,
        r: SCRYPT_BLOCK_SIZE,
        p: SCRYPT_PARALLELIZATION,
        maxmem: SCRYPT_MAX_MEMORY,
      },
      (error, derivedKey) => (error === null ? resolve(derivedKey) : reject(error)),
    );
  });
}
