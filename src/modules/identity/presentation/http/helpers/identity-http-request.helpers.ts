import { IdentityHttpRequest } from '../interfaces/identity-http-request';
import { Optional } from '#shared/types/absence.types';

export function readCsrfHeader(request: IdentityHttpRequest): Optional<string> {
  const value = request.headers['x-csrf-token'];
  return Array.isArray(value) ? undefined : value;
}
