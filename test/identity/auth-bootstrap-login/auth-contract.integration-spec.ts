import { randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { Writable } from 'node:stream';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import request from 'supertest';

import { AppModule } from '../../../src/app.module';
import { createIdentityDataSource } from '../../../src/shared/database/identity-database-options';
import { ApplicationOptions, configureApplication } from '../../../src/main';
import {
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresPlan,
  startIsolatedPostgres,
} from '../../support/isolated-postgres-harness';

const ORIGIN = 'http://localhost:4200';

describe('Identity authentication public contract', () => {
  let app: INestApplication;
  let plan: IsolatedPostgresPlan;
  let cleanup: (() => Promise<void>) | undefined;
  let previousEnvironment: Map<string, string | undefined>;
  let logOutput = '';

  beforeAll(async () => {
    previousEnvironment = captureEnvironment();
    plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(
        randomBytes(32).toString('hex'),
        await selectLoopbackPort(),
      ),
    );
    const run = await startIsolatedPostgres(plan);
    cleanup = (): Promise<void> => run.cleanup();
    await run.migrate({ createDataSource: createIdentityDataSource });
    applyEnvironment(plan);
    app = await NestFactory.create(AppModule, { abortOnError: false, logger: false });
    configureApplication(
      app,
      new ApplicationOptions(
        undefined,
        new Writable({
          write(chunk, _encoding, callback): void {
            logOutput += chunk.toString();
            callback();
          },
        }),
      ),
    );
    await app.init();
  });

  afterAll(async () => {
    if (app !== undefined) await app.close();
    if (cleanup !== undefined) await cleanup();
    restoreEnvironment(previousEnvironment);
  });

  it('documents the three auth routes, the pre-auth cookie, and header-only CSRF admission', async () => {
    const document = await request(app.getHttpServer()).get('/api/v1/docs-json').expect(200);
    const paths = readRecord(document.body, 'paths');
    const csrf = readRecord(paths, '/api/v1/auth/csrf');
    const register = readRecord(paths, '/api/v1/auth/register');
    const login = readRecord(paths, '/api/v1/auth/login');

    expect(readRecord(csrf, 'get').security).toBeUndefined();
    expect(readRecord(register, 'post')).toMatchObject({ security: [{ preAuthSession: [] }] });
    expect(readRecord(login, 'post')).toMatchObject({ security: [{ preAuthSession: [] }] });
    expect(readRecord(document.body, 'components')).toMatchObject({
      securitySchemes: {
        preAuthSession: { type: 'apiKey', in: 'cookie', name: '__Host-session' },
      },
    });

    for (const operation of [readRecord(register, 'post'), readRecord(login, 'post')]) {
      expect(readHeaderParameter(operation, 'Origin')).toMatchObject({
        in: 'header',
        name: 'Origin',
        required: true,
      });
      expect(readHeaderParameter(operation, 'X-CSRF-Token')).toMatchObject({
        in: 'header',
        name: 'X-CSRF-Token',
        required: true,
      });
    }
    expect(readHeaderParameter(readRecord(csrf, 'get'), 'Cookie')).toMatchObject({
      required: false,
    });
    expect(readHeaderParameter(readRecord(csrf, 'get'), 'Origin')).toMatchObject({
      required: false,
    });
    expect(readResponseHeader(readRecord(csrf, 'get'), '200', 'Set-Cookie')).toBeDefined();
    expect(readResponseHeader(readRecord(register, 'post'), '201', 'Set-Cookie')).toBeDefined();
    expect(readResponseHeader(readRecord(login, 'post'), '200', 'Set-Cookie')).toBeDefined();
    expect(readResponseHeader(readRecord(login, 'post'), '401', 'Set-Cookie')).toBeDefined();
  });

  it('emits a legitimate safe Pino completion event without request secrets', async () => {
    const passwordMarker = 'pino-password-marker';
    const recordMarker = 'pino-record-marker';
    const tokenMarker = 'pino-token-marker';
    const csrfMarker = 'pino-csrf-marker';
    const urlMarker = 'pino-url-marker';
    const hmacSecret = process.env.IDENTITY_THROTTLE_HMAC_SECRET;
    if (hmacSecret === undefined) throw new Error('Expected test HMAC secret.');
    const response = await request(app.getHttpServer())
      .post(`/api/v1/auth/login?token=${urlMarker}`)
      .set('Origin', ORIGIN)
      .set('Cookie', `__Host-session=${tokenMarker}`)
      .set('X-CSRF-Token', csrfMarker)
      .send({ email: recordMarker, password: passwordMarker })
      .expect(401);

    expect(response.body.code).toBe('AUTHENTICATION_REQUIRED');
    expect(logOutput).toContain('http_request_completed');
    for (const marker of [
      passwordMarker,
      recordMarker,
      tokenMarker,
      csrfMarker,
      urlMarker,
      hmacSecret,
    ]) {
      expect(logOutput).not.toContain(marker);
    }
    expect(logOutput).not.toContain('__Host-session');
    expect(logOutput).not.toContain('set-cookie');
  });
});

function readRecord(value: unknown, key: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`Expected object at ${key}.`);
  }
  const result = (value as Record<string, unknown>)[key];
  if (typeof result !== 'object' || result === null || Array.isArray(result)) {
    throw new Error(`Expected object value for ${key}.`);
  }
  return result as Record<string, unknown>;
}

function readHeaderParameter(
  operation: Record<string, unknown>,
  name: string,
): Record<string, unknown> | undefined {
  const parameters = operation.parameters;
  if (!Array.isArray(parameters)) return undefined;
  return parameters.find(
    (parameter): parameter is Record<string, unknown> =>
      typeof parameter === 'object' &&
      parameter !== null &&
      !Array.isArray(parameter) &&
      parameter.name === name,
  );
}

function readResponseHeader(
  operation: Record<string, unknown>,
  status: string,
  header: string,
): unknown {
  const responses = readRecord(operation, 'responses');
  const response = readRecord(responses, status);
  return readRecord(readRecord(response, 'headers'), header);
}

function captureEnvironment(): Map<string, string | undefined> {
  return new Map(
    [
      'DATABASE_HOST',
      'DATABASE_PORT',
      'DATABASE_USERNAME',
      'DATABASE_PASSWORD',
      'DATABASE_NAME',
      'DATABASE_SCHEMA',
      'IDENTITY_THROTTLE_HMAC_SECRET',
      'NODE_ENV',
      'CORS_ALLOWED_ORIGINS',
    ].map((key) => [key, process.env[key]]),
  );
}

function applyEnvironment(plan: IsolatedPostgresPlan): void {
  process.env.NODE_ENV = 'test';
  process.env.CORS_ALLOWED_ORIGINS = ORIGIN;
  process.env.IDENTITY_THROTTLE_HMAC_SECRET = randomBytes(32).toString('base64url');
  process.env.DATABASE_HOST = plan.environment.IDENTITY_TEST_POSTGRES_HOST;
  process.env.DATABASE_PORT = plan.environment.IDENTITY_TEST_POSTGRES_PORT;
  process.env.DATABASE_USERNAME = plan.environment.IDENTITY_TEST_DATABASE_USER;
  process.env.DATABASE_PASSWORD = plan.environment.IDENTITY_TEST_DATABASE_PASSWORD;
  process.env.DATABASE_NAME = plan.databaseName;
  process.env.DATABASE_SCHEMA = plan.schemaName;
}

function restoreEnvironment(previous: Map<string, string | undefined>): void {
  for (const [key, value] of previous) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

function selectLoopbackPort(): Promise<number> {
  return new Promise((resolvePort, rejectPort) => {
    const server = createServer();
    server.once('error', rejectPort);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close(() => rejectPort(new Error('No loopback port.')));
        return;
      }
      server.close((error) =>
        error === undefined ? resolvePort(address.port) : rejectPort(error),
      );
    });
  });
}
