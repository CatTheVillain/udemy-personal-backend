import { ForbiddenException, HttpStatus, UnauthorizedException } from '@nestjs/common';
import { Response } from 'express';

import {
  CsrfBootstrapRejection,
  IdentityAuthenticationFailure,
  InitialPreAuthCheck,
} from '../../../application/authentication/contracts/identity-authentication.contracts';
import { PasswordWorkRejection } from '../../../application/credentials/contracts/password-work.contracts';
import {
  DurableThrottleRejection,
  ThrottleAdmissionRejection,
} from '../../../domain/identity.types';
import { PublicProblemException } from '#shared/http/public-problem.exception';
import { clearIdentitySessionCookie } from '../cookies/identity-session-cookie';

type DurableThrottleProblemCode = 'registration_rate_limited' | 'login_rate_limited';

export function translateAuthenticationFailure(error: unknown, response: Response): never {
  if (error instanceof IdentityAuthenticationFailure) {
    if (error.kind === 'csrf_invalid') {
      throw new PublicProblemException(HttpStatus.FORBIDDEN, 'CSRF_INVALID');
    }
    if (error.kind === 'unauthorized') {
      clearIdentitySessionCookie(response);
      throw new UnauthorizedException();
    }
    throw new ForbiddenException();
  }
  throw error;
}

export function throwPasswordWorkRejection(
  result: PasswordWorkRejection,
  response: Response,
): never {
  response.setHeader('Retry-After', String(result.retryAfterSeconds));
  if (result.kind === 'rate_limited') {
    throw new PublicProblemException(HttpStatus.TOO_MANY_REQUESTS, 'password_work_rate_limited');
  }
  if (result.kind === 'busy') {
    throw new PublicProblemException(HttpStatus.SERVICE_UNAVAILABLE, 'password_work_busy');
  }
  throw new PublicProblemException(HttpStatus.SERVICE_UNAVAILABLE, 'password_work_unavailable');
}

export function isDurableThrottleRejection(result: unknown): result is DurableThrottleRejection {
  return (
    typeof result === 'object' &&
    result !== null &&
    'kind' in result &&
    (result as { readonly kind: unknown }).kind === 'durable_rate_limited'
  );
}

export function throwDurableThrottleRejection(
  result: DurableThrottleRejection,
  response: Response,
  code: DurableThrottleProblemCode,
): never {
  response.setHeader('Retry-After', String(result.retryAfterSeconds));
  throw new PublicProblemException(HttpStatus.TOO_MANY_REQUESTS, code);
}

export function isThrottleAdmissionRejection(
  result: unknown,
): result is ThrottleAdmissionRejection {
  return (
    typeof result === 'object' &&
    result !== null &&
    'kind' in result &&
    ((result as { readonly kind: unknown }).kind === 'throttle_busy' ||
      (result as { readonly kind: unknown }).kind === 'throttle_capacity_unavailable')
  );
}

export function throwThrottleAdmissionRejection(
  result: ThrottleAdmissionRejection,
  response: Response,
): never {
  response.setHeader('Retry-After', String(result.retryAfterSeconds));
  throw new PublicProblemException(HttpStatus.SERVICE_UNAVAILABLE, result.kind);
}

export function isCsrfBootstrapRejection(
  result: InitialPreAuthCheck | CsrfBootstrapRejection,
): result is CsrfBootstrapRejection {
  return (
    result.kind === 'rate_limited' ||
    result.kind === 'unavailable' ||
    result.kind === 'busy' ||
    result.kind === 'capacity_unavailable'
  );
}

export function throwCsrfBootstrapRejection(
  result: CsrfBootstrapRejection,
  response: Response,
): never {
  response.setHeader('Retry-After', String(result.retryAfterSeconds));
  if (result.kind === 'rate_limited') {
    throw new PublicProblemException(HttpStatus.TOO_MANY_REQUESTS, 'csrf_bootstrap_rate_limited');
  }
  if (result.kind === 'unavailable') {
    throw new PublicProblemException(HttpStatus.SERVICE_UNAVAILABLE, 'csrf_bootstrap_unavailable');
  }
  if (result.kind === 'busy') {
    throw new PublicProblemException(HttpStatus.SERVICE_UNAVAILABLE, 'csrf_bootstrap_busy');
  }
  throw new PublicProblemException(
    HttpStatus.SERVICE_UNAVAILABLE,
    'csrf_bootstrap_capacity_unavailable',
  );
}
