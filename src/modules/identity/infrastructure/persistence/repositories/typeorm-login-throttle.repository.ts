import { randomUUID } from 'node:crypto';
import { EntityManager } from 'typeorm';

import { LoginThrottleRepositoryPort } from '../../../application/ports/identity.ports';
import {
  LoginThrottle,
  LoginThrottleLookup,
  ThrottleAdmissionResult,
  ThrottleWindowInput,
} from '../../../domain/identity.types';
import { LoginThrottleEntity } from '../entities/login-throttle.entity';
import { LoginThrottlePersistenceMapper } from '../mappers/login-throttle.persistence-mapper';

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

  public async acquireForLogin(input: ThrottleWindowInput): Promise<LoginThrottle> {
    const repository = this.entityManager.getRepository(LoginThrottleEntity);
    await repository
      .createQueryBuilder()
      .insert()
      .into(LoginThrottleEntity)
      .values({
        id: randomUUID(),
        keyHash: input.keyHash,
        windowStartedAt: input.now,
        expiresAt: input.expiresAt,
        failureCount: 0,
      })
      .orIgnore()
      .execute();
    const entity = await repository.findOne({
      where: { keyHash: input.keyHash },
      lock: { mode: 'pessimistic_write' },
    });
    if (entity === null) throw new Error('Unable to acquire login throttle.');

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
    if (entity.failureCount >= 5) return { admitted: false };
    if (entity.failureCount === 0) {
      entity.windowStartedAt = now;
      entity.expiresAt = new Date(now.getTime() + 15 * 60 * 1000);
    }
    entity.failureCount += 1;
    await repository.save(entity);
    return { admitted: true };
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
}
