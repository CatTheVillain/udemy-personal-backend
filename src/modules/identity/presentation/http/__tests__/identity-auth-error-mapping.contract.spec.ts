import { HttpStatus } from '@nestjs/common';
import { ExecutionContextHost } from '@nestjs/core/helpers/execution-context-host';
import { Response } from 'express';

import {
  CsrfBootstrapOutcome,
  CsrfBootstrapRejection,
  IdentityAuthenticationFailure,
  PreAuthContext,
} from '../../../application/authentication/contracts/identity-authentication.contracts';
import { IdentityAuthenticationService } from '../../../application/authentication/services/identity-authentication.service';
import { AuthEmailPasswordRequestDto } from '../dto/auth-email-password.request.dto';
import { IdentityHttpRequest } from '../interfaces/identity-http-request';
import { IdentityAuthController } from '../controllers/identity-auth.controller';
import { ProblemDetailsFilter } from '#shared/http/problem-details.filter';
import type { Optional } from '#shared/types/absence.types';

interface CapturedProblemBody {
  readonly code: string;
  readonly detail: string;
}

interface CapturedProblem {
  readonly status: number;
  readonly type: string;
  readonly body: CapturedProblemBody;
}

interface CapturedFailure {
  readonly exception: unknown;
  readonly clearCookieCallsAtFailure: number;
  readonly cookieCallsAtFailure: number;
}

interface ResponseCapture {
  readonly response: Response;
  readonly clearCookie: jest.Mock;
  readonly cookie: jest.Mock;
  readonly headers: ReadonlyMap<string, unknown>;
  readonly capturedProblem: () => Optional<CapturedProblem>;
}

type AuthenticationOutcomes = Partial<
  Pick<IdentityAuthenticationService, 'bootstrapCsrf' | 'register' | 'login'>
>;

type CsrfBootstrapCase = readonly [string, CsrfBootstrapRejection, number, string, string];

type MappedAuthenticationRejection =
  | { readonly kind: 'rate_limited'; readonly retryAfterSeconds: number }
  | { readonly kind: 'busy'; readonly retryAfterSeconds: number }
  | { readonly kind: 'unavailable'; readonly retryAfterSeconds: number }
  | { readonly kind: 'durable_rate_limited'; readonly retryAfterSeconds: number }
  | { readonly kind: 'throttle_busy'; readonly retryAfterSeconds: 1 }
  | { readonly kind: 'throttle_capacity_unavailable'; readonly retryAfterSeconds: 60 };

type AuthenticationMappingCase = readonly [
  string,
  'register' | 'login',
  MappedAuthenticationRejection,
  number,
  string,
  string,
];

const PRE_AUTH: PreAuthContext = {
  sessionId: 'pre-auth-session',
  tokenHash: 'token-hash',
  csrfTokenHash: 'csrf-hash',
};

const CSRF_BOOTSTRAP_CASES: readonly CsrfBootstrapCase[] = [
  [
    'rate limited',
    { kind: 'rate_limited', retryAfterSeconds: 12 },
    429,
    'csrf_bootstrap_rate_limited',
    '12',
  ],
  [
    'unavailable',
    { kind: 'unavailable', retryAfterSeconds: 60 },
    503,
    'csrf_bootstrap_unavailable',
    '60',
  ],
  ['busy', { kind: 'busy', retryAfterSeconds: 1 }, 503, 'csrf_bootstrap_busy', '1'],
  [
    'capacity unavailable',
    { kind: 'capacity_unavailable', retryAfterSeconds: 60 },
    503,
    'csrf_bootstrap_capacity_unavailable',
    '60',
  ],
];

const AUTHENTICATION_MAPPING_CASES: readonly AuthenticationMappingCase[] = [
  [
    'register password rate limit',
    'register',
    { kind: 'rate_limited', retryAfterSeconds: 7 },
    429,
    'password_work_rate_limited',
    '7',
  ],
  [
    'register password busy',
    'register',
    { kind: 'busy', retryAfterSeconds: 8 },
    503,
    'password_work_busy',
    '8',
  ],
  [
    'register password unavailable',
    'register',
    { kind: 'unavailable', retryAfterSeconds: 9 },
    503,
    'password_work_unavailable',
    '9',
  ],
  [
    'register durable throttle',
    'register',
    { kind: 'durable_rate_limited', retryAfterSeconds: 10 },
    429,
    'registration_rate_limited',
    '10',
  ],
  [
    'login durable throttle',
    'login',
    { kind: 'durable_rate_limited', retryAfterSeconds: 11 },
    429,
    'login_rate_limited',
    '11',
  ],
  [
    'register admission busy',
    'register',
    { kind: 'throttle_busy', retryAfterSeconds: 1 },
    503,
    'throttle_busy',
    '1',
  ],
  [
    'login admission capacity',
    'login',
    { kind: 'throttle_capacity_unavailable', retryAfterSeconds: 60 },
    503,
    'throttle_capacity_unavailable',
    '60',
  ],
];

describe('Identity HTTP error mapping characterization', () => {
  it.each([
    [
      'csrf-invalid failure',
      new IdentityAuthenticationFailure('csrf_invalid'),
      HttpStatus.FORBIDDEN,
      'CSRF_INVALID',
      false,
    ],
    [
      'unauthorized failure',
      new IdentityAuthenticationFailure('unauthorized'),
      HttpStatus.UNAUTHORIZED,
      'AUTHENTICATION_REQUIRED',
      true,
    ],
    [
      'forbidden failure',
      new IdentityAuthenticationFailure('forbidden'),
      HttpStatus.FORBIDDEN,
      'ACCESS_DENIED',
      false,
    ],
  ])(
    'renders %s through the real controller and Problem Details filter',
    async (_name, rejection, expectedStatus, expectedCode, expectsCookieClear) => {
      const capture = responseCapture();
      const controller = controllerFor({
        bootstrapCsrf: async (): Promise<CsrfBootstrapOutcome> => {
          throw rejection;
        },
      });

      const failure = await captureFailure(
        () => controller.bootstrapCsrf(undefined, identityRequest(), capture.response),
        capture,
      );
      renderProblem(failure.exception, capture.response);

      expect(capture.capturedProblem()).toMatchObject({
        status: expectedStatus,
        type: 'application/problem+json',
        body: { code: expectedCode },
      });
      expect(capture.clearCookie).toHaveBeenCalledTimes(expectsCookieClear ? 1 : 0);
      expect(failure.clearCookieCallsAtFailure).toBe(expectsCookieClear ? 1 : 0);
      if (expectsCookieClear) {
        expect(capture.clearCookie).toHaveBeenCalledWith('__Host-session', {
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
          path: '/',
        });
      }
      expect(capture.cookie).not.toHaveBeenCalled();
    },
  );

  it('rethrows an unknown error unchanged and the real filter renders a safe internal problem', async () => {
    const marker = 'synthetic-identity-error-marker';
    const rejection = new Error(marker);
    const capture = responseCapture();
    const controller = controllerFor({
      bootstrapCsrf: async (): Promise<CsrfBootstrapOutcome> => {
        throw rejection;
      },
    });

    const failure = await captureFailure(
      () => controller.bootstrapCsrf(undefined, identityRequest(), capture.response),
      capture,
    );
    expect(failure.exception).toBe(rejection);
    renderProblem(failure.exception, capture.response);

    expect(capture.capturedProblem()).toMatchObject({
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      type: 'application/problem+json',
      body: {
        code: 'INTERNAL_ERROR',
        detail: 'An unexpected error occurred.',
      },
    });
    expect(JSON.stringify(capture.capturedProblem())).not.toContain(marker);
    expect(capture.clearCookie).not.toHaveBeenCalled();
  });

  it.each(AUTHENTICATION_MAPPING_CASES)(
    'preserves %s status, code, string Retry-After, and no cookie',
    async (_name, route, outcome, expectedStatus, expectedCode, expectedRetryAfter) => {
      const capture = responseCapture();
      const controller = controllerFor({
        register: async () => outcome,
        login: async () => outcome,
      });

      const failure =
        route === 'register'
          ? await captureFailure(
              () => controller.register(authBody(), PRE_AUTH, identityRequest(), capture.response),
              capture,
            )
          : await captureFailure(
              () => controller.login(authBody(), PRE_AUTH, identityRequest(), capture.response),
              capture,
            );
      renderProblem(failure.exception, capture.response);

      expect(capture.capturedProblem()).toMatchObject({
        status: expectedStatus,
        type: 'application/problem+json',
        body: { code: expectedCode },
      });
      expectStringHeader(capture, 'retry-after', expectedRetryAfter);
      expectNoCookieWrite(capture);
    },
  );

  it.each(CSRF_BOOTSTRAP_CASES)(
    'preserves CSRF bootstrap %s mapping through the real filter',
    async (_name, outcome, expectedStatus, expectedCode, expectedRetryAfter) => {
      const capture = responseCapture();
      const controller = controllerFor({
        bootstrapCsrf: async (): Promise<CsrfBootstrapOutcome> => outcome,
      });

      const failure = await captureFailure(
        () => controller.bootstrapCsrf(undefined, identityRequest(), capture.response),
        capture,
      );
      renderProblem(failure.exception, capture.response);

      expect(capture.capturedProblem()).toMatchObject({
        status: expectedStatus,
        type: 'application/problem+json',
        body: { code: expectedCode },
      });
      expectStringHeader(capture, 'retry-after', expectedRetryAfter);
      expectNoCookieWrite(capture);
    },
  );

  it('retains the bootstrap forbidden fallback outside the rejection predicate', async () => {
    const capture = responseCapture();
    const controller = controllerFor({
      bootstrapCsrf: async (): Promise<CsrfBootstrapOutcome> => ({ kind: 'forbidden' }),
    });

    const failure = await captureFailure(
      () => controller.bootstrapCsrf(undefined, identityRequest(), capture.response),
      capture,
    );
    renderProblem(failure.exception, capture.response);

    expect(capture.capturedProblem()).toMatchObject({
      status: HttpStatus.FORBIDDEN,
      type: 'application/problem+json',
      body: { code: 'ACCESS_DENIED' },
    });
    expect(capture.headers.get('retry-after')).toBeUndefined();
    expectNoCookieWrite(capture);
  });
});

function controllerFor(outcomes: AuthenticationOutcomes): IdentityAuthController {
  return new IdentityAuthController(outcomes as IdentityAuthenticationService);
}

function authBody(): AuthEmailPasswordRequestDto {
  return {
    email: 'student@example.test',
    password: 'a valid password',
  } as AuthEmailPasswordRequestDto;
}

function identityRequest(): IdentityHttpRequest {
  return {
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
  } as IdentityHttpRequest;
}

async function captureFailure(
  action: () => Promise<unknown>,
  capture: ResponseCapture,
): Promise<CapturedFailure> {
  try {
    await action();
  } catch (error: unknown) {
    return {
      exception: error,
      clearCookieCallsAtFailure: capture.clearCookie.mock.calls.length,
      cookieCallsAtFailure: capture.cookie.mock.calls.length,
    };
  }
  throw new Error('Expected the controller to reject.');
}

function expectStringHeader(capture: ResponseCapture, name: string, expected: string): void {
  const value = capture.headers.get(name);
  expect(value).toBe(expected);
  expect(typeof value).toBe('string');
}

function expectNoCookieWrite(capture: ResponseCapture): void {
  expect(capture.clearCookie).not.toHaveBeenCalled();
  expect(capture.cookie).not.toHaveBeenCalled();
  expect(capture.headers.get('set-cookie')).toBeUndefined();
}

function renderProblem(exception: unknown, response: Response): void {
  const host = new ExecutionContextHost([{}, response]);
  host.setType('http');
  new ProblemDetailsFilter().catch(exception, host);
}

function responseCapture(): ResponseCapture {
  const headers = new Map<string, unknown>();
  let captured: Optional<CapturedProblem>;
  const response = {} as Response;
  const clearCookie = jest.fn();
  const cookie = jest.fn();

  response.headersSent = false;
  response.locals = { requestId: '1d39fb4e-69c1-4b90-9db2-90afb77d91c2' };
  response.setHeader = jest.fn((name: string, value: string | number | string[]): Response => {
    headers.set(name.toLowerCase(), value);
    return response;
  });
  response.clearCookie = clearCookie;
  response.cookie = cookie;
  response.status = jest.fn((status: number): Response => {
    captured = { status, type: '', body: { code: '', detail: '' } };
    return response;
  });
  response.type = jest.fn((type: string): Response => {
    if (captured === undefined) throw new Error('Expected status before content type.');
    captured = { ...captured, type };
    return response;
  });
  response.send = jest.fn((body: CapturedProblemBody): Response => {
    if (captured === undefined) throw new Error('Expected status before response body.');
    captured = { ...captured, body };
    return response;
  });

  return {
    response,
    clearCookie,
    cookie,
    headers,
    capturedProblem: (): Optional<CapturedProblem> => captured,
  };
}
