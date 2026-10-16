import { randomUUID } from 'node:crypto';
import { EntityManager } from 'typeorm';

import { RegistrationThrottleRepositoryPort } from '../../../application/ports/identity.ports';
import {
  RegistrationThrottle,
  RegistrationThrottleLookup,
  ThrottleAdmissionResult,
  ThrottleWindowInput,
} from '../../../domain/identity.types';
import { RegistrationThrottleEntity } from '../entities/registration-throttle.entity';
import { RegistrationThrottlePersistenceMapper } from '../mappers/registration-throttle.persistence-mapper';

const THROTTLE_CAPACITY = 10_000;
const THROTTLE_CLEANUP_LIMIT = 256;
const REGISTRATION_ADVISORY_LOCK = 734_111_003;

interface AdvisoryLockRow {
  readonly locked: boolean;
}

interface PopulationRow {
  readonly population: number;
}

export class TypeOrmRegistrationThrottleRepository implements RegistrationThrottleRepositoryPort {
  public constructor(private readonly entityManager: EntityManager) {}

  public async findByKeyAndWindow(
    lookup: RegistrationThrottleLookup,
  ): Promise<RegistrationThrottle | null> {
    const entity = await this.entityManager.getRepository(RegistrationThrottleEntity).findOneBy({
      keyHash: lookup.keyHash,
      windowStartedAt: lookup.windowStartedAt,
    });
    return entity === null ? null : RegistrationThrottlePersistenceMapper.toDomain(entity);
  }

  public async save(throttle: RegistrationThrottle): Promise<void> {
    await this.entityManager
      .getRepository(RegistrationThrottleEntity)
      .save(RegistrationThrottlePersistenceMapper.toEntity(throttle));
  }

  public async consumeAttempt(input: ThrottleWindowInput): Promise<ThrottleAdmissionResult> {
    const repository = this.entityManager.getRepository(RegistrationThrottleEntity);
    let entity = await repository.findOne({
      where: { keyHash: input.keyHash },
      lock: { mode: 'pessimistic_write' },
    });
    if (entity === null) {
      const admission = await this.admitFirstSeen(input);
      if (admission.kind !== 'admitted') return admission;
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
          attemptCount: 0,
        });
      }
    }

    if (entity.expiresAt <= input.now) {
      entity.windowStartedAt = input.now;
      entity.expiresAt = input.expiresAt;
      entity.attemptCount = 1;
      await repository.save(entity);
      return { kind: 'admitted' };
    }
    if (entity.attemptCount >= 3) {
      return { kind: 'durable_rate_limited', expiresAt: entity.expiresAt };
    }

    entity.attemptCount += 1;
    await repository.save(entity);
    return { kind: 'admitted' };
  }

  private async admitFirstSeen(input: ThrottleWindowInput): Promise<ThrottleAdmissionResult> {
    const table = this.entityManager.getRepository(RegistrationThrottleEntity).metadata.tablePath;
    const lock = await this.entityManager.query<AdvisoryLockRow[]>(
      'SELECT pg_try_advisory_xact_lock($1) AS locked',
      [REGISTRATION_ADVISORY_LOCK],
    );
    if (lock[0]?.locked !== true) return { kind: 'throttle_busy', retryAfterSeconds: 1 };

    const initialPopulation = await this.readPopulation(table);
    await this.cleanupExpired(table);
    if (initialPopulation > THROTTLE_CAPACITY) {
      return { kind: 'throttle_capacity_unavailable', retryAfterSeconds: 60 };
    }
    const postCleanupPopulation = await this.readPopulation(table);
    if (postCleanupPopulation >= THROTTLE_CAPACITY) {
      return { kind: 'throttle_capacity_unavailable', retryAfterSeconds: 60 };
    }
    return { kind: 'admitted' };
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
