import { randomUUID } from 'node:crypto';
import { EntityManager } from 'typeorm';

import { LoginThrottleRepositoryPort } from '../../../application/ports/identity.ports';
import {
  LoginThrottle,
  LoginThrottleLookup,
  LOGIN_FAILURE_LIMIT,
  ThrottleAdmissionRejection,
  ThrottleAdmissionResult,
  ThrottleWindowInput,
} from '../../../domain/identity.types';
import { LoginThrottleEntity } from '../entities/login-throttle.entity';
import { LoginThrottlePersistenceMapper } from '../mappers/login-throttle.persistence-mapper';

const THROTTLE_CAPACITY = 10_000;
const THROTTLE_CLEANUP_LIMIT = 256;
const LOGIN_ADVISORY_LOCK = 734_111_004;

interface AdvisoryLockRow {
  readonly locked: boolean;
}

interface PopulationRow {
  readonly population: number;
}

export class TypeOrmLoginThrottleRepository implements LoginThrottleRepositoryPort {
  public constructor(private readonly entityManager: EntityManager) {}

  public async findByKeyAndWindow(lookup: LoginThrottleLookup): Promise<LoginThrottle | null> {
    const entity = await this.entityManager.getRepository(LoginThrottleEntity).findOneBy({
      keyHash: lookup.keyHash,
      windowStartedAt: lookup.windowStartedAt,
    });
    return entity === null ? null : LoginThrottlePersistenceMapper.toDomain(entity);
  }

  public async save(throttle: LoginThrottle): Promise<void> {
    await this.entityManager
      .getRepository(LoginThrottleEntity)
      .save(LoginThrottlePersistenceMapper.toEntity(throttle));
  }

  public async acquireForLogin(
    input: ThrottleWindowInput,
  ): Promise<LoginThrottle | ThrottleAdmissionRejection> {
    const repository = this.entityManager.getRepository(LoginThrottleEntity);
    let entity = await repository.findOne({
      where: { keyHash: input.keyHash },
      lock: { mode: 'pessimistic_write' },
    });
    if (entity === null) {
      const admission = await this.admitFirstSeen();
      if (admission !== null) return admission;
      entity = await repository.findOne({
        where: { keyHash: input.keyHash },
        lock: { mode: 'pessimistic_write' },
      });
      if (entity === null) {
        entity = repository.create({
          id: randomUUID(),
          keyHash: input.keyHash,
          windowStartedAt: input.now,
          expiresAt: input.expiresAt,
          failureCount: 0,
        });
        await repository.save(entity);
      }
    }

    if (entity.expiresAt <= input.now) {
      entity.windowStartedAt = input.now;
      entity.expiresAt = input.expiresAt;
      entity.failureCount = 0;
      await repository.save(entity);
    }
    return LoginThrottlePersistenceMapper.toDomain(entity);
  }

  public async consumeFailure(keyHash: string, now: Date): Promise<ThrottleAdmissionResult> {
    const repository = this.entityManager.getRepository(LoginThrottleEntity);
    const entity = await repository.findOne({
      where: { keyHash },
      lock: { mode: 'pessimistic_write' },
    });
    if (entity === null || entity.expiresAt <= now) {
      throw new Error('Login throttle must be acquired before a failure is consumed.');
    }
    if (entity.failureCount >= LOGIN_FAILURE_LIMIT) return { kind: 'rate_limited' };
    if (entity.failureCount === 0) {
      entity.windowStartedAt = now;
      entity.expiresAt = new Date(now.getTime() + 15 * 60 * 1000);
    }
    entity.failureCount += 1;
    await repository.save(entity);
    return { kind: 'admitted' };
  }

  public async resetFailures(keyHash: string, now: Date): Promise<void> {
    const repository = this.entityManager.getRepository(LoginThrottleEntity);
    const entity = await repository.findOne({
      where: { keyHash },
      lock: { mode: 'pessimistic_write' },
    });
    if (entity === null) throw new Error('Login throttle must be acquired before reset.');
    entity.failureCount = 0;
    entity.windowStartedAt = now;
    entity.expiresAt = new Date(now.getTime() + 15 * 60 * 1000);
    await repository.save(entity);
  }

  private async admitFirstSeen(): Promise<ThrottleAdmissionRejection | null> {
    const table = this.entityManager.getRepository(LoginThrottleEntity).metadata.tablePath;
    const lock = await this.entityManager.query<AdvisoryLockRow[]>(
      'SELECT pg_try_advisory_xact_lock($1) AS locked',
      [LOGIN_ADVISORY_LOCK],
    );
    if (lock[0]?.locked !== true) return { kind: 'throttle_busy', retryAfterSeconds: 1 };

    const initialPopulation = await this.readPopulation(table);
    await this.cleanupExpired(table);
    if (initialPopulation > THROTTLE_CAPACITY) {
      return { kind: 'throttle_capacity_unavailable', retryAfterSeconds: 60 };
    }
    const postCleanupPopulation = await this.readPopulation(table);
    return postCleanupPopulation >= THROTTLE_CAPACITY
      ? { kind: 'throttle_capacity_unavailable', retryAfterSeconds: 60 }
      : null;
  }

  private async cleanupExpired(table: string): Promise<void> {
    await this.entityManager.query(
      `WITH candidates AS MATERIALIZED (
         SELECT id
         FROM ${table}
         WHERE expires_at <= clock_timestamp()
         ORDER BY expires_at, id
         LIMIT ${THROTTLE_CLEANUP_LIMIT}
         FOR UPDATE SKIP LOCKED
       )
       DELETE FROM ${table} AS throttles
       USING candidates
       WHERE throttles.id = candidates.id
         AND throttles.expires_at <= clock_timestamp()`,
    );
  }

  private async readPopulation(table: string): Promise<number> {
    const rows = await this.entityManager.query<PopulationRow[]>(
      `SELECT count(*)::int AS population
       FROM (SELECT 1 FROM ${table} LIMIT ${THROTTLE_CAPACITY + 1}) AS retained`,
    );
    return rows[0]?.population ?? THROTTLE_CAPACITY + 1;
  }
}
