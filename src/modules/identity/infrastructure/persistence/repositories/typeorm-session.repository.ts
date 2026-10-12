import { EntityManager } from 'typeorm';

import { SessionRepositoryPort } from '../../../application/ports/identity.ports';
import {
  ConsumePreAuthSessionInput,
  RevokeActiveSessionInput,
  RotatePreAuthCsrfInput,
  Session,
  SessionTransitionResult,
} from '../../../domain/identity.types';
import { SessionEntity } from '../entities/session.entity';
import { SessionPersistenceMapper } from '../mappers/session.persistence-mapper';

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
}

function toSessionTransitionResult(affected: number | null | undefined): SessionTransitionResult {
  if (affected === 0) return { affectedRows: 0 };
  if (affected === 1) return { affectedRows: 1 };
  throw new Error('Unexpected session transition result.');
}
