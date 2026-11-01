import { ParsedScryptRecord } from '../contracts/scrypt-password.contracts';
import type { Nullable } from '#shared/types/absence.types';

export function parseScryptRecord(record: string): Nullable<ParsedScryptRecord> {
  const parts = record.split('$');
  if (
    parts.length !== 7 ||
    parts[0] !== 'scrypt' ||
    parts[1] !== 'v1' ||
    parts[2] !== '131072' ||
    parts[3] !== '8' ||
    parts[4] !== '1'
  )
    return null;
  const saltValue = parts[5];
  const keyValue = parts[6];
  if (saltValue === undefined || keyValue === undefined) return null;
  const salt = Buffer.from(saltValue, 'base64url');
  const key = Buffer.from(keyValue, 'base64url');
  if (
    salt.length !== 16 ||
    key.length !== 64 ||
    salt.toString('base64url') !== saltValue ||
    key.toString('base64url') !== keyValue
  )
    return null;
  return { salt, key };
}
