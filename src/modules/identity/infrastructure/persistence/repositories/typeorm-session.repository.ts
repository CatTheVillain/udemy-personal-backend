import { EntityManager } from 'typeorm';

import { SessionRepositoryPort } from '../../../application/ports/identity.ports';
import {
  ConsumePreAuthSessionInput,
  BootstrapPreAuthSessionAdmission,
  BootstrapPreAuthSessionInput,
  RevokeActiveSessionInput,
  RotatePreAuthCsrfInput,
  Session,
  SessionTransitionResult,
} from '../../../domain/identity.types';
import { SessionEntity } from '../entities/session.entity';
import { SessionPersistenceMapper } from '../mappers/session.persistence-mapper';

interface AdvisoryLockRow {
  readonly locked: boolean;
}

interface BootstrapPopulationRow {
  readonly population: number;
}

export class TypeOrmSessionRepository implements SessionRepositoryPort {
  public constructor(private readonly entityManager: EntityManager) {}

  public async insert(session: Session): Promise<void> {
    await this.entityManager
      .getRepository(SessionEntity)
      .insert(SessionPersistenceMapper.toEntity(session));
  }

  public async findById(id: string): Promise<Session | null> {
    const entity = await this.entityManager.getRepository(SessionEntity).findOneBy({ id });
    return entity === null ? null : SessionPersistenceMapper.toDomain(entity);
  }

  public async findByTokenHash(tokenHash: string): Promise<Session | null> {
    const entity = await this.entityManager.getRepository(SessionEntity).findOneBy({ tokenHash });
    return entity === null ? null : SessionPersistenceMapper.toDomain(entity);
  }

  public async findLockedById(id: string): Promise<Session | null> {
    const entity = await this.entityManager.getRepository(SessionEntity).findOne({
      where: { id },
      lock: { mode: 'pessimistic_write' },
    });
    return entity === null ? null : SessionPersistenceMapper.toDomain(entity);
  }

  public async rotateActivePreAuthCsrf(
    input: RotatePreAuthCsrfInput,
  ): Promise<SessionTransitionResult> {
    const result = await this.entityManager
      .createQueryBuilder()
      .update(SessionEntity)
      .set({ csrfTokenHash: input.csrfTokenHash, lastSeenAt: input.now })
      .where('id = :id', { id: input.id })
      .andWhere('token_hash = :tokenHash', { tokenHash: input.tokenHash })
      .andWhere("state = 'pre_auth'")
      .andWhere('revoked_at IS NULL')
      .andWhere('absolute_expires_at > :now', { now: input.now })
      .andWhere('idle_expires_at > :now', { now: input.now })
      .execute();
    return toSessionTransitionResult(result.affected);
  }

  public async consumeLockedPreAuth(
    input: ConsumePreAuthSessionInput,
  ): Promise<SessionTransitionResult> {
    const result = await this.entityManager
      .createQueryBuilder()
      .update(SessionEntity)
      .set({ state: 'revoked', revokedAt: input.now })
      .where('id = :id', { id: input.id })
      .andWhere('token_hash = :tokenHash', { tokenHash: input.tokenHash })
      .andWhere('csrf_token_hash = :csrfTokenHash', { csrfTokenHash: input.csrfTokenHash })
      .andWhere("state = 'pre_auth'")
      .andWhere('revoked_at IS NULL')
      .andWhere('absolute_expires_at > :now', { now: input.now })
      .andWhere('idle_expires_at > :now', { now: input.now })
      .execute();
    return toSessionTransitionResult(result.affected);
  }

  public async revokeActiveSession(
    input: RevokeActiveSessionInput,
  ): Promise<SessionTransitionResult> {
    const result = await this.entityManager
      .createQueryBuilder()
      .update(SessionEntity)
      .set({ state: 'revoked', revokedAt: input.now })
      .where('id = :id', { id: input.id })
      .andWhere('token_hash = :tokenHash', { tokenHash: input.tokenHash })
      .andWhere("state IN ('pre_auth', 'authenticated')")
      .andWhere('revoked_at IS NULL')
      .andWhere('absolute_expires_at > :now', { now: input.now })
      .andWhere('idle_expires_at > :now', { now: input.now })
      .execute();
    return toSessionTransitionResult(result.affected);
  }

  public async admitBootstrapPreAuthSession(
    input: BootstrapPreAuthSessionInput,
  ): Promise<BootstrapPreAuthSessionAdmission> {
    const table = this.entityManager.getRepository(SessionEntity).metadata.tablePath;
    const lock = await this.entityManager.query<AdvisoryLockRow[]>(
      'SELECT pg_try_advisory_xact_lock(734_111_002) AS locked',
    );
    if (lock[0]?.locked !== true) return { kind: 'busy' };

    await this.entityManager.query(
      `WITH expired AS MATERIALIZED (
         SELECT id, absolute_expires_at AS eligible_at
         FROM ${table}
         WHERE state = 'pre_auth' AND absolute_expires_at <= $1
         ORDER BY absolute_expires_at, id
         LIMIT 256
       ), revoked AS MATERIALIZED (
         SELECT id, revoked_at AS eligible_at
         FROM ${table}
         WHERE state = 'revoked' AND user_id IS NULL
         ORDER BY revoked_at, id
         LIMIT 256
       ), candidates AS MATERIALIZED (
         SELECT id, eligible_at FROM expired
         UNION ALL
         SELECT id, eligible_at FROM revoked
         ORDER BY eligible_at, id
         LIMIT 256
       ), locked AS MATERIALIZED (
         SELECT sessions.id
         FROM ${table} AS sessions
         JOIN candidates ON candidates.id = sessions.id
         ORDER BY candidates.eligible_at, candidates.id
         FOR UPDATE OF sessions SKIP LOCKED
       )
       DELETE FROM ${table} AS sessions
       USING locked
       WHERE sessions.id = locked.id
         AND ((sessions.state = 'pre_auth' AND sessions.absolute_expires_at <= $1)
              OR (sessions.state = 'revoked' AND sessions.user_id IS NULL))`,
      [input.now],
    );

    const population = await this.entityManager.query<BootstrapPopulationRow[]>(
      `SELECT count(*)::int AS population
       FROM (
         SELECT 1
         FROM ${table}
         WHERE state = 'pre_auth'
            OR (state = 'revoked' AND user_id IS NULL)
         LIMIT 10001
       ) AS capped_population`,
    );
    if ((population[0]?.population ?? 10_001) >= 10_000) {
      return { kind: 'capacity_unavailable' };
    }
    await this.insert(input.session);
    return { kind: 'created' };
  }
}

function toSessionTransitionResult(affected: number | null | undefined): SessionTransitionResult {
  if (affected === 0) return { affectedRows: 0 };
  if (affected === 1) return { affectedRows: 1 };
  throw new Error('Unexpected session transition result.');
}
