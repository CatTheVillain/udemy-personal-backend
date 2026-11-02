import { applyDecorators } from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiCookieAuth,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiHeader,
  ApiHeaderOptions,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiResponseNoStatusOptions,
  ApiServiceUnavailableResponse,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
  HeadersObject,
  getSchemaPath,
} from '@nestjs/swagger';

import { ProblemDetailsDto } from '#shared/http/problem-details';
import {
  AuthenticatedIdentityApiResponseDto,
  CsrfBootstrapApiResponseDto,
  LoginApiResponseDto,
  RegistrationApiResponseDto,
} from '../dto/auth-response.dto';
import type { Optional } from '#shared/types/absence.types';

export function ApiBootstrapCsrfDocumentation(): MethodDecorator {
  return applyDecorators(
    ApiOperation({ summary: 'Bootstrap or rotate the CSRF token for the current session' }),
    ApiHeader(optionalHeader('Origin', 'Optional configured browser origin.')),
    ApiHeader(optionalHeader('Cookie', 'Optional __Host-session cookie.')),
    ApiOkResponse({
      type: CsrfBootstrapApiResponseDto,
      headers: cookieHeader('A new or unchanged session cookie.'),
    }),
    ApiUnauthorizedResponse(
      problem(
        'Invalid, expired, revoked, or logged-out supplied session; clears the supplied cookie.',
        'Clears the invalid session cookie.',
      ),
    ),
    ApiForbiddenResponse(problem('Disallowed origin')),
    ApiTooManyRequestsResponse(
      problem(
        'CSRF bootstrap source quota is exhausted (csrf_bootstrap_rate_limited).',
        undefined,
        'Retry time.',
      ),
    ),
    ApiServiceUnavailableResponse(
      problem(
        'CSRF bootstrap admission is temporarily unavailable (csrf_bootstrap_unavailable, csrf_bootstrap_busy, or csrf_bootstrap_capacity_unavailable).',
        undefined,
        'Advisory retry time.',
      ),
    ),
  );
}

export function ApiAuthenticatedIdentityDocumentation(): MethodDecorator {
  return applyDecorators(
    ApiOperation({
      summary: 'Read the current authenticated identity without renewing the session',
    }),
    ApiCookieAuth('preAuthSession'),
    ApiHeader(requiredHeader('Cookie', 'Current authenticated __Host-session cookie.')),
    ApiOkResponse({ type: AuthenticatedIdentityApiResponseDto }),
    ApiUnauthorizedResponse(
      problem(
        'Missing, invalid, expired, revoked, or logged-out authenticated session; clears the supplied cookie.',
        'Clears the invalid session cookie.',
      ),
    ),
    ApiServiceUnavailableResponse(problem('Current access facts are temporarily unavailable.')),
  );
}

export function ApiLogoutDocumentation(): MethodDecorator {
  return applyDecorators(
    ApiOperation({ summary: 'Revoke the current authenticated session without renewing it' }),
    ApiCookieAuth('preAuthSession'),
    ApiHeader({ name: 'X-CSRF-Token', required: true }),
    ApiHeader(requiredHeader('Origin', 'Configured browser origin.')),
    ApiNoContentResponse({ headers: cookieHeader('Clears the revoked session cookie.') }),
    ApiUnauthorizedResponse(
      problem(
        'Invalid, expired, revoked, or logged-out authenticated session; clears the supplied cookie.',
        'Clears the invalid session cookie.',
      ),
    ),
    ApiForbiddenResponse(problem('Origin or CSRF validation failed')),
  );
}

export function ApiRegisterDocumentation(): MethodDecorator {
  return preAuthDocumentation(
    ApiOperation({ summary: 'Register a normal base account without authenticating it' }),
    ApiCreatedResponse({
      type: RegistrationApiResponseDto,
      headers: cookieHeader('Clears the consumed pre-auth session cookie after commit.'),
    }),
    ApiConflictResponse(problem('The email is already registered')),
    'Registration or password-work throttle is exhausted',
  );
}

export function ApiLoginDocumentation(): MethodDecorator {
  return preAuthDocumentation(
    ApiOperation({ summary: 'Authenticate with a pre-auth CSRF session' }),
    ApiOkResponse({
      type: LoginApiResponseDto,
      headers: cookieHeader('Sets a fresh authenticated session cookie after commit.'),
    }),
    undefined,
    'Login or password-work throttle is exhausted',
    problem(
      'Credentials are invalid or pre-auth is invalid. The cookie is cleared only for invalid pre-auth.',
      'Clears the cookie only when the pre-auth session is invalid; absent for credentials_invalid.',
    ),
  );
}

function preAuthDocumentation(
  operation: MethodDecorator,
  success: MethodDecorator,
  conflict: Optional<MethodDecorator>,
  throttleDescription: string,
  unauthorized = problem(
    'Invalid pre-auth session; clears the supplied cookie.',
    'Clears the invalid cookie.',
  ),
): MethodDecorator {
  return applyDecorators(
    operation,
    ApiCookieAuth('preAuthSession'),
    ApiHeader({ name: 'X-CSRF-Token', required: true }),
    ApiHeader(requiredHeader('Origin', 'Configured browser origin.')),
    success,
    ApiBadRequestResponse(problem('Invalid request body')),
    ApiUnauthorizedResponse(unauthorized),
    ApiForbiddenResponse(problem('Origin or CSRF validation failed')),
    ...(conflict === undefined ? [] : [conflict]),
    ApiTooManyRequestsResponse(problem(throttleDescription, undefined, 'Retry time.')),
    ApiServiceUnavailableResponse(
      problem(
        'Password-work or durable throttle capacity is temporarily unavailable',
        undefined,
        'Advisory retry time.',
      ),
    ),
  );
}

function problem(
  description: string,
  cookieDescription?: string,
  retryAfterDescription?: string,
): ApiResponseNoStatusOptions {
  const response: ApiResponseNoStatusOptions = {
    description,
    content: { 'application/problem+json': { schema: { $ref: getSchemaPath(ProblemDetailsDto) } } },
  };
  if (cookieDescription !== undefined) response.headers = cookieHeader(cookieDescription);
  if (retryAfterDescription !== undefined)
    response.headers = retryAfterHeader(retryAfterDescription);
  return response;
}

function retryAfterHeader(description: string): HeadersObject {
  return { 'Retry-After': { description, schema: { type: 'string' } } };
}
function optionalHeader(name: string, description: string): ApiHeaderOptions {
  return { name, required: false, description, schema: { type: 'string' } };
}
function requiredHeader(name: string, description: string): ApiHeaderOptions {
  return { name, required: true, description, schema: { type: 'string' } };
}
function cookieHeader(description: string): HeadersObject {
  return { 'Set-Cookie': { description, schema: { type: 'string' } } };
}
