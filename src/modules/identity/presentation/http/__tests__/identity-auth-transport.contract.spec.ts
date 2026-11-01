import { ExecutionContext } from '@nestjs/common';
import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants';
import { ExecutionContextHost } from '@nestjs/core/helpers/execution-context-host';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { Test } from '@nestjs/testing';
import { Response } from 'express';
import { readFileSync } from 'fs';
import { IncomingHttpHeaders } from 'http';
import { resolve } from 'path';

import {
  AuthenticatedSessionContext,
  AuthenticatedSessionCheck,
  InitialPreAuthCheck,
  PreAuthContext,
  IdentityAccessFactsUnavailableFailure,
} from '../../../application/authentication/contracts/identity-authentication.contracts';
import { IdentityAuthenticationService } from '../../../application/authentication/services/identity-authentication.service';
import { IdentityAuthController } from '../controllers/identity-auth.controller';
import { AuthenticatedCsrfGuard } from '../guards/authenticated-csrf.guard';
import { PreAuthCsrfGuard } from '../guards/pre-auth-csrf.guard';
import { readCsrfHeader } from '../helpers/identity-http-request.helpers';
import {
  AuthenticatedIdentityHttpRequest,
  IdentityHttpRequest,
} from '../interfaces/identity-http-request';

type AuthenticationTransportCollaborator = Pick<
  IdentityAuthenticationService,
  'checkAuthenticatedCsrf' | 'checkInitialPreAuth' | 'getAuthenticatedIdentity'
>;

interface DecoratorMetadataEntry {
  readonly factory?: RouteArgumentFactory;
}

interface RouteArgumentFactory {
  (data: unknown, context: ExecutionContext): unknown;
}

interface RouteArgumentMetadata {
  readonly [key: string]: DecoratorMetadataEntry;
}

interface OpenApiContractFixture {
  readonly paths: Record<string, unknown>;
  readonly components?: Record<string, unknown>;
}

const expectedOpenApiContract = JSON.parse(
  readFileSync(
    resolve(__dirname, '../../../../../../test/fixtures/identity-auth-openapi.expected.json'),
    'utf8',
  ),
) as OpenApiContractFixture;

describe('Identity HTTP transport contracts', () => {
  it('keeps CSRF header absence semantics', () => {
    expect(readCsrfHeader(identityRequest({}))).toBeUndefined();
    expect(readCsrfHeader(identityRequest({ 'x-csrf-token': 'csrf' }))).toBe('csrf');
    expect(readCsrfHeader(identityRequest({ 'x-csrf-token': ['csrf', 'other'] }))).toBeUndefined();
  });

  it('passes an absence-preserving named pre-auth input and exposes accepted context', async () => {
    const checkInitialPreAuth = jest.fn(async (): Promise<InitialPreAuthCheck> => ({
      kind: 'accepted',
      context: { sessionId: 'pre', tokenHash: 'token', csrfTokenHash: 'csrf' },
    }));
    const request = identityRequest({
      cookie: 'other=value',
      origin: 'https://allowed.example',
      'x-csrf-token': ['csrf'],
    });
    const guard = new PreAuthCsrfGuard(authenticationService({ checkInitialPreAuth }));

    await expect(guard.canActivate(executionContextFor(request))).resolves.toBe(true);
    expect(checkInitialPreAuth).toHaveBeenCalledWith({
      cookieValue: undefined,
      csrfToken: undefined,
      origin: 'https://allowed.example',
    });
    expect(request.identityPreAuth).toEqual({
      sessionId: 'pre',
      tokenHash: 'token',
      csrfTokenHash: 'csrf',
    });
  });

  it('passes an absence-preserving named authenticated input and exposes accepted context', async () => {
    const checkAuthenticatedCsrf = jest.fn(async (): Promise<AuthenticatedSessionCheck> => ({
      kind: 'accepted',
      context: { sessionId: 'auth', tokenHash: 'token', csrfTokenHash: 'csrf' },
    }));
    const request = authenticatedIdentityRequest({
      cookie: '__Host-session=opaque',
      origin: undefined,
      'x-csrf-token': 'csrf',
    });
    const guard = new AuthenticatedCsrfGuard(authenticationService({ checkAuthenticatedCsrf }));

    await expect(guard.canActivate(executionContextFor(request))).resolves.toBe(true);
    expect(checkAuthenticatedCsrf).toHaveBeenCalledWith({
      cookieValue: 'opaque',
      csrfToken: 'csrf',
      origin: undefined,
    });
    expect(request.identityAuthenticated).toEqual({
      sessionId: 'auth',
      tokenHash: 'token',
      csrfTokenHash: 'csrf',
    });
  });

  it('binds guard-established contexts through the controller decorators', () => {
    const preAuth = { sessionId: 'pre', tokenHash: 'token', csrfTokenHash: 'csrf' };
    const authenticated = {
      sessionId: 'auth',
      tokenHash: 'token',
      csrfTokenHash: 'csrf',
    };
    const registerDecorator = customFactory('register');
    const logoutDecorator = customFactory('logout');

    expect(registerDecorator(undefined, executionContextFor(identityRequest({}, preAuth)))).toBe(
      preAuth,
    );
    expect(
      logoutDecorator(
        undefined,
        executionContextFor(authenticatedIdentityRequest({}, authenticated)),
      ),
    ).toBe(authenticated);
    expect(() => registerDecorator(undefined, executionContextFor(identityRequest({})))).toThrow(
      'Unauthorized',
    );
  });

  it('translates only unavailable access facts to the established safe 503', async () => {
    const controller = new IdentityAuthController(
      authenticationService({
        getAuthenticatedIdentity: jest
          .fn()
          .mockRejectedValue(new IdentityAccessFactsUnavailableFailure()),
      }),
    );

    await expect(
      controller.getAuthenticatedIdentity('opaque', responseStub()),
    ).rejects.toMatchObject({
      status: 503,
      response: { statusCode: 503, message: 'Service Unavailable' },
    });
  });

  it('rethrows an unknown identity-read failure unchanged', async () => {
    const failure = new Error('unexpected');
    const controller = new IdentityAuthController(
      authenticationService({
        getAuthenticatedIdentity: jest.fn().mockRejectedValue(failure),
      }),
    );

    await expect(controller.getAuthenticatedIdentity('opaque', responseStub())).rejects.toBe(
      failure,
    );
  });

  it('preserves the complete public OpenAPI paths and components contract', async () => {
    const module = await Test.createTestingModule({
      controllers: [IdentityAuthController],
      providers: [
        {
          provide: IdentityAuthenticationService,
          useValue: authenticationService({}),
        },
      ],
    }).compile();
    const app = module.createNestApplication();
    app.setGlobalPrefix('api/v1');
    await app.init();
    try {
      const document = SwaggerModule.createDocument(app, new DocumentBuilder().build());
      expect({ paths: document.paths, components: document.components }).toEqual(
        expectedOpenApiContract,
      );
    } finally {
      await app.close();
    }
  });
});

function authenticationService(
  collaborator: Partial<AuthenticationTransportCollaborator>,
): IdentityAuthenticationService {
  return collaborator as IdentityAuthenticationService;
}

function identityRequest(
  headers: IncomingHttpHeaders,
  identityPreAuth?: PreAuthContext,
): IdentityHttpRequest {
  return { headers, identityPreAuth } as IdentityHttpRequest;
}

function authenticatedIdentityRequest(
  headers: IncomingHttpHeaders,
  identityAuthenticated?: AuthenticatedSessionContext,
): AuthenticatedIdentityHttpRequest {
  return { headers, identityAuthenticated } as AuthenticatedIdentityHttpRequest;
}

function responseStub(): Response {
  const response = Object.create(Response.prototype) as Response;
  response.setHeader = jest.fn();
  return response;
}

function executionContextFor(request: IdentityHttpRequest): ExecutionContext {
  return new ExecutionContextHost([request, responseStub()]);
}

function customFactory(method: string): RouteArgumentFactory {
  const metadata = Reflect.getMetadata(ROUTE_ARGS_METADATA, IdentityAuthController, method) as
    RouteArgumentMetadata | undefined;
  const entry = metadata === undefined ? undefined : Object.values(metadata).find(isCustomFactory);
  if (entry?.factory === undefined) {
    throw new Error(`Missing custom decorator for ${method}`);
  }
  return entry.factory;
}

function isCustomFactory(entry: DecoratorMetadataEntry): boolean {
  return typeof entry.factory === 'function';
}
