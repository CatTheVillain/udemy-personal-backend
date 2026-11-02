import { Response } from 'express';
import type { Optional } from '#shared/types/absence.types';

const SESSION_COOKIE_NAME = '__Host-session';

export function readIdentitySessionCookie(header: Optional<string>): Optional<string> {
  if (header === undefined) return undefined;
  let value: Optional<string>;
  for (const part of header.split(';')) {
    const pair = part.trimStart();
    const separator = pair.indexOf('=');
    if (separator < 0) {
      if (pair === SESSION_COOKIE_NAME) return '';
      continue;
    }
    if (pair.slice(0, separator) !== SESSION_COOKIE_NAME) continue;
    if (value !== undefined) return '';
    value = pair.slice(separator + 1);
  }
  return value;
}

export function setIdentitySessionCookie(response: Response, value: string): void {
  response.cookie(SESSION_COOKIE_NAME, value, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
  });
}

export function clearIdentitySessionCookie(response: Response): void {
  response.clearCookie(SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
  });
}
