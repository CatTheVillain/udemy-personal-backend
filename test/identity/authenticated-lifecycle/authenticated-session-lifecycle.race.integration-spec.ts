import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';

import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import request, { Response } from 'supertest';
import { DataSource, QueryRunner } from 'typeorm';

import { AppModule } from '../../../src/app.module';
import { SessionEntity } from '../../../src/modules/identity/infrastructure/persistence/entities/session.entity';
import { createIdentityDataSource } from '../../../src/shared/database/identity-database-options';
import { configureApplication } from '../../../src/main';
import {
  createIsolatedPostgresDatabaseOptions,
  createIsolatedPostgresEnvironment,
  createIsolatedPostgresPlan,
  IsolatedPostgresPlan,
  startIsolatedPostgres,
} from '../../support/isolated-postgres-harness';

const ORIGIN = 'http://localhost:4200';
const PASSWORD = 'literal valid password';
const BARRIER_LOCK_KEY = 734_003_004;
type Fixture = { readonly cookie: string; readonly csrf: string; readonly session: SessionEntity };
type Receipt = {
  readonly blockerPid: number;
  readonly pid: number;
  readonly query: string;
  readonly waitEvent: string;
};

describe('Authenticated session database lifecycle race', () => {
  let app: INestApplication;
  let observer: DataSource;
  let plan: IsolatedPostgresPlan;
  let cleanup: (() => Promise<void>) | undefined;
  let previous: Map<string, string | undefined>;

  beforeAll(async () => {
    previous = environment();
    plan = createIsolatedPostgresPlan(
      createIsolatedPostgresEnvironment(randomBytes(32).toString('hex'), await port()),
    );
    const run = await startIsolatedPostgres(plan);
    cleanup = (): Promise<void> => run.cleanup();
    await run.migrate({ createDataSource: createIdentityDataSource });
    apply(plan);
    observer = createIdentityDataSource(createIsolatedPostgresDatabaseOptions(plan));
    await observer.initialize();
  });
  beforeEach(async () => {
    app = await NestFactory.create(AppModule, { abortOnError: false, logger: false });
    configureApplication(app);
    await app.init();
  });
  afterEach(async () => {
    if (app !== undefined) await app.close();
  });
  afterAll(async () => {
    if (observer?.isInitialized) await observer.destroy();
    if (cleanup !== undefined) await cleanup();
    restore(previous);
  });

  it('AC03 rejects a CSRF touch after the real database clock crosses expiry while the exact row is locked', async () => {
    const fixture = await createFixture('expiry-touch@example.test');
    await nearExpiry(fixture.session.id);
    const before = await session(fixture.session.id);
    const holder = await hold(fixture.session.id);
    try {
      const pending = csrf(fixture.cookie);
      const contender = await waitForLock(1);
      expect(contender[0]?.pid).not.toBe(holder.pid);
      await databaseExpired(fixture.session.id);
      await holder.runner.commitTransaction();
      const response = await pending;
      expect(response.status).toBe(401);
      expect(response.body.code).toBe('AUTHENTICATION_REQUIRED');
      expect(cookie(response)).toContain('__Host-session=;');
      const after = await session(fixture.session.id);
      expect(after.csrfTokenHash).toBe(before.csrfTokenHash);
      expect(after.lastSeenAt.getTime()).toBe(before.lastSeenAt.getTime());
      expect((await csrf((await createFixture('valid-control@example.test')).cookie)).status).toBe(
        200,
      );
    } finally {
      await release(holder.runner);
    }
  });

  it('AC03 makes /me readonly and rejects it after the same physical post-lock expiry', async () => {
    const fixture = await createFixture('expiry-me@example.test');
    await nearExpiry(fixture.session.id);
    const before = await session(fixture.session.id);
    const holder = await hold(fixture.session.id);
    try {
      const pending = request(app.getHttpServer())
        .get('/api/v1/auth/me')
        .set('Cookie', fixture.cookie)
        .then((response) => response);
      const contender = await waitForLock(1);
      expect(contender[0]?.pid).not.toBe(holder.pid);
      await databaseExpired(fixture.session.id);
      await holder.runner.commitTransaction();
      const response = await pending;
      expect(response.status).toBe(401);
      expect(cookie(response)).toContain('__Host-session=;');
      const after = await session(fixture.session.id);
      expect(after.csrfTokenHash).toBe(before.csrfTokenHash);
      expect(after.lastSeenAt.getTime()).toBe(before.lastSeenAt.getTime());
    } finally {
      await release(holder.runner);
    }
  });

  it('AC04 commits logout before a delayed CSRF touch, then /me and CSRF remain terminally denied', async () => {
    const fixture = await createFixture('logout-first@example.test');
    const gate = await barrier();
    try {
      const logoutPending = logoutRequest(fixture.cookie, fixture.csrf);
      const logoutWaiter = await waitForAdvisory(1);
      const delayed = csrf(fixture.cookie);
      const logoutPid = logoutWaiter[0]?.pid;
      if (logoutPid === undefined) throw new Error('Expected logout advisory waiter PID.');
      expect(logoutWaiter[0]?.blockerPid).toBe(gate.pid);
      expect(logoutWaiter[0]?.waitEvent).toBe('advisory');
      const touchWaiter = await waitForLock(1, [logoutPid]);
      expect(touchWaiter[0]?.blockerPid).toBe(logoutPid);
      expect(touchWaiter[0]?.waitEvent).toBe('transactionid');
      expect(new Set([gate.pid, logoutPid, touchWaiter[0]?.pid]).size).toBe(3);
      await releaseBarrier(gate.runner);
      const [logoutResponse, touch] = await Promise.all([logoutPending, delayed]);
      expect(logoutResponse.status).toBe(204);
      expect(touch.status).toBe(401);
      expect(
        (await request(app.getHttpServer()).get('/api/v1/auth/me').set('Cookie', fixture.cookie))
          .status,
      ).toBe(401);
      const final = await session(fixture.session.id);
      expect(final.state).toBe('revoked');
      expect(final.revokedAt).not.toBeNull();
      expect(final.lastSeenAt.getTime()).toBe(fixture.session.lastSeenAt.getTime());
    } finally {
      await unbarrier(gate.runner);
      await release(gate.runner);
    }
  });

  it('AC04 permits touch-first then terminal fresh-CSRF logout, denying later CSRF and /me', async () => {
    const fixture = await createFixture('touch-first@example.test');
    const gate = await barrier();
    try {
      const touch = csrf(fixture.cookie);
      const waiter = await waitForAdvisory(1);
      expect(waiter[0]?.pid).not.toBe(gate.pid);
      await releaseBarrier(gate.runner);
      const touched = await touch;
      expect(touched.status).toBe(200);
      expect((await logoutRequest(fixture.cookie, csrfToken(touched))).status).toBe(204);
      const [nextCsrf, me] = await Promise.all([
        csrf(fixture.cookie),
        request(app.getHttpServer()).get('/api/v1/auth/me').set('Cookie', fixture.cookie),
      ]);
      expect(nextCsrf.status).toBe(401);
      expect(me.status).toBe(401);
      expect((await session(fixture.session.id)).state).toBe('revoked');
    } finally {
      await unbarrier(gate.runner);
      await release(gate.runner);
    }
  });

  it('AC04 proves the observed barrier admits two unsafe stale updates while guarded authenticated CSRF succeeds once', async () => {
    const fixture = await createFixture('unsafe-control@example.test');
    await observer.query(
      `UPDATE "${plan.schemaName}".identity_sessions SET state = 'revoked', revoked_at = clock_timestamp() WHERE id = $1`,
      [fixture.session.id],
    );
    const gate = await barrier();
    const first = observer.createQueryRunner();
    const second = observer.createQueryRunner();
    await Promise.all([
      first.connect(),
      second.connect(),
      first.startTransaction(),
      second.startTransaction(),
    ]);
    try {
      const pids = await Promise.all([pid(first), pid(second)]);
      const a = unsafe(first, fixture.session.id);
      await waitForAdvisoryPids([pids[0] as number]);
      const b = unsafe(second, fixture.session.id);
      await waitForAdvisoryPids(pids as number[]);
      await releaseBarrier(gate.runner);
      await expect(a).resolves.toBe(1);
      await first.commitTransaction();
      await expect(b).resolves.toBe(1);
      await second.commitTransaction();
      const unsafeFinal = await session(fixture.session.id);
      expect(unsafeFinal.state).toBe('authenticated');
      expect(unsafeFinal.revokedAt).toBeNull();
      expect(
        (await csrf((await createFixture('guarded-control@example.test')).cookie)).status,
      ).toBe(200);
    } finally {
      await unbarrier(gate.runner);
      await release(gate.runner);
      await release(first);
      await release(second);
    }
  });

  async function createFixture(email: string): Promise<Fixture> {
    const initial = await bootstrap();
    await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .set('Origin', ORIGIN)
      .set('Cookie', initial.cookie)
      .set('X-CSRF-Token', initial.csrf)
      .send({ email, password: PASSWORD })
      .expect(201);
    const loginCsrf = await bootstrap();
    const login = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .set('Origin', ORIGIN)
      .set('Cookie', loginCsrf.cookie)
      .set('X-CSRF-Token', loginCsrf.csrf)
      .send({ email, password: PASSWORD })
      .expect(200);
    const currentCookie = firstCookie(login);
    const rotated = await csrf(currentCookie);
    expect(rotated.status).toBe(200);
    return {
      cookie: currentCookie,
      csrf: csrfToken(rotated),
      session: await observer
        .getRepository(SessionEntity)
        .findOneByOrFail({ tokenHash: hash(value(currentCookie)) }),
    };
  }
  async function bootstrap(): Promise<{ readonly cookie: string; readonly csrf: string }> {
    const response = await request(app.getHttpServer()).get('/api/v1/auth/csrf').expect(200);
    return { cookie: firstCookie(response), csrf: csrfToken(response) };
  }
  function csrf(currentCookie: string): Promise<Response> {
    return request(app.getHttpServer())
      .get('/api/v1/auth/csrf')
      .set('Cookie', currentCookie)
      .then((response) => response);
  }
  function logoutRequest(currentCookie: string, csrfValue: string): Promise<Response> {
    return request(app.getHttpServer())
      .post('/api/v1/auth/logout')
      .set('Origin', ORIGIN)
      .set('Cookie', currentCookie)
      .set('X-CSRF-Token', csrfValue)
      .then((response) => response);
  }
  async function session(id: string): Promise<SessionEntity> {
    return observer.getRepository(SessionEntity).findOneByOrFail({ id });
  }
  async function nearExpiry(id: string): Promise<void> {
    await observer.query(
      `UPDATE "${plan.schemaName}".identity_sessions SET idle_expires_at = clock_timestamp() + INTERVAL '2 seconds', absolute_expires_at = clock_timestamp() + INTERVAL '3 seconds' WHERE id = $1`,
      [id],
    );
  }
  async function hold(id: string): Promise<{ readonly runner: QueryRunner; readonly pid: number }> {
    const runner = observer.createQueryRunner();
    await runner.connect();
    await runner.startTransaction();
    const backend = await pid(runner);
    await runner.query(
      `SELECT id FROM "${plan.schemaName}".identity_sessions WHERE id = $1 FOR UPDATE`,
      [id],
    );
    return { runner, pid: backend };
  }
  async function barrier(): Promise<{ readonly runner: QueryRunner; readonly pid: number }> {
    const runner = observer.createQueryRunner();
    await runner.connect();
    const backend = await pid(runner);
    await runner.query(
      `CREATE FUNCTION "${plan.schemaName}".authenticated_session_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(${BARRIER_LOCK_KEY}); RETURN NEW; END; $$; CREATE TRIGGER authenticated_session_barrier BEFORE UPDATE ON "${plan.schemaName}".identity_sessions FOR EACH STATEMENT EXECUTE FUNCTION "${plan.schemaName}".authenticated_session_barrier();`,
    );
    await runner.startTransaction();
    await runner.query('SELECT pg_advisory_xact_lock($1)', [BARRIER_LOCK_KEY]);
    return { runner, pid: backend };
  }
  async function releaseBarrier(runner: QueryRunner): Promise<void> {
    if (runner.isTransactionActive) await runner.commitTransaction();
  }
  async function unbarrier(runner: QueryRunner): Promise<void> {
    if (runner.isTransactionActive) await runner.rollbackTransaction();
    await runner.query(
      `DROP TRIGGER IF EXISTS authenticated_session_barrier ON "${plan.schemaName}".identity_sessions; DROP FUNCTION IF EXISTS "${plan.schemaName}".authenticated_session_barrier();`,
    );
  }
  async function waitForLock(
    minimum: number,
    excluded: readonly number[] = [],
  ): Promise<readonly Receipt[]> {
    return wait(
      minimum,
      excluded,
      `activity.wait_event_type = 'Lock' AND activity.wait_event = 'transactionid'`,
    );
  }
  async function waitForAdvisory(minimum: number): Promise<readonly Receipt[]> {
    return wait(
      minimum,
      [],
      `locks.locktype = 'advisory' AND NOT locks.granted`,
      'INNER JOIN pg_locks AS locks ON locks.pid = activity.pid',
    );
  }
  async function waitForAdvisoryPids(expected: readonly number[]): Promise<void> {
    const receipts = await waitForAdvisory(expected.length);
    expect(receipts.map((receipt) => receipt.pid)).toEqual(expect.arrayContaining([...expected]));
  }
  async function wait(
    minimum: number,
    excluded: readonly number[],
    predicate: string,
    join = '',
  ): Promise<readonly Receipt[]> {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      const receipts = readReceipts(
        await observer.query(
          `SELECT activity.pid::int AS pid, activity.query, (pg_blocking_pids(activity.pid))[1]::int AS "blockerPid", activity.wait_event AS "waitEvent" FROM pg_stat_activity AS activity ${join} WHERE activity.datname=$1 AND cardinality(pg_blocking_pids(activity.pid)) > 0 AND ${predicate}`,
          [plan.databaseName],
        ),
      );
      const selected = receipts.filter((receipt) => !excluded.includes(receipt.pid));
      if (selected.length >= minimum) return selected;
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
    throw new Error(`Race barrier did not observe ${minimum} waiting PostgreSQL statement(s).`);
  }
  async function databaseExpired(id: string): Promise<void> {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      if (
        readBoolean(
          await observer.query(
            `SELECT clock_timestamp() >= idle_expires_at AS expired FROM "${plan.schemaName}".identity_sessions WHERE id=$1`,
            [id],
          ),
          'expired',
        )
      )
        return;
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
    throw new Error('PostgreSQL clock did not reach controlled expiry.');
  }
});

async function pid(runner: QueryRunner): Promise<number> {
  return number(await runner.query('SELECT pg_backend_pid()::int AS pid'), 'pid');
}
async function release(runner: QueryRunner): Promise<void> {
  if (runner.isTransactionActive) await runner.rollbackTransaction();
  if (!runner.isReleased) await runner.release();
}
async function unsafe(runner: QueryRunner, id: string): Promise<number> {
  const schema = process.env.DATABASE_SCHEMA;
  if (schema === undefined) throw new Error('Expected owned database schema.');
  return number(
    await runner.query(
      `WITH updated AS (UPDATE "${schema}".identity_sessions SET state = 'authenticated', revoked_at = NULL, last_seen_at = clock_timestamp() WHERE id = $1 RETURNING id) SELECT count(*)::int AS affected FROM updated`,
      [id],
    ),
    'affected',
  );
}
function environment(): Map<string, string | undefined> {
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
function apply(plan: IsolatedPostgresPlan): void {
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
function restore(previous: Map<string, string | undefined>): void {
  for (const [key, current] of previous) {
    if (current === undefined) delete process.env[key];
    else process.env[key] = current;
  }
}
function firstCookie(response: Response): string {
  const current = cookie(response);
  if (current === undefined) throw new Error('Expected session cookie.');
  return current.split(';')[0] ?? '';
}
function cookie(response: Response): string | undefined {
  const current = response.headers['set-cookie'];
  return Array.isArray(current) && typeof current[0] === 'string' ? current[0] : undefined;
}
function value(current: string): string {
  const token = current.split('=', 2)[1];
  if (token === undefined) throw new Error('Expected cookie token.');
  return token;
}
function csrfToken(response: Response): string {
  const token = response.body?.data?.csrfToken;
  if (typeof token !== 'string') throw new Error('Expected CSRF token.');
  return token;
}
function hash(current: string): string {
  return createHash('sha256').update(current, 'utf8').digest('hex');
}
function readReceipts(value: unknown): readonly Receipt[] {
  if (!Array.isArray(value)) throw new Error('Expected PostgreSQL wait receipts.');
  return value.map((row) => {
    if (typeof row !== 'object' || row === null || Array.isArray(row))
      throw new Error('Expected PostgreSQL wait record.');
    const record = row as Record<string, unknown>;
    if (
      typeof record.pid !== 'number' ||
      typeof record.query !== 'string' ||
      typeof record.blockerPid !== 'number' ||
      typeof record.waitEvent !== 'string'
    )
      throw new Error('Expected PostgreSQL wait fields.');
    return {
      blockerPid: record.blockerPid,
      pid: record.pid,
      query: record.query,
      waitEvent: record.waitEvent,
    };
  });
}
function number(value: unknown, field: string): number {
  const result = record(value);
  const current = result[field];
  if (typeof current !== 'number') throw new Error(`Expected numeric ${field}.`);
  return current;
}
function readBoolean(value: unknown, field: string): boolean {
  const current = record(value)[field];
  if (typeof current !== 'boolean') throw new Error(`Expected boolean ${field}.`);
  return current;
}
function record(value: unknown): Record<string, unknown> {
  if (
    !Array.isArray(value) ||
    value.length !== 1 ||
    typeof value[0] !== 'object' ||
    value[0] === null ||
    Array.isArray(value[0])
  )
    throw new Error('Expected one PostgreSQL record.');
  return value[0] as Record<string, unknown>;
}
function port(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close(() => reject(new Error('No loopback port.')));
        return;
      }
      server.close((error) => (error === undefined ? resolve(address.port) : reject(error)));
    });
  });
}
