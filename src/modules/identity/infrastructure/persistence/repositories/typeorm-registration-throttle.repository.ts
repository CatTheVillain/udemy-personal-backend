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
    await repository
      .createQueryBuilder()
      .insert()
      .into(RegistrationThrottleEntity)
      .values({
        id: randomUUID(),
        keyHash: input.keyHash,
        windowStartedAt: input.now,
        expiresAt: input.expiresAt,
        attemptCount: 0,
      })
      .orIgnore()
      .execute();
    const entity = await repository.findOne({
      where: { keyHash: input.keyHash },
      lock: { mode: 'pessimistic_write' },
    });
    if (entity === null) throw new Error('Unable to acquire registration throttle.');

    if (entity.expiresAt <= input.now) {
      entity.windowStartedAt = input.now;
      entity.expiresAt = input.expiresAt;
      entity.attemptCount = 1;
      await repository.save(entity);
      return { admitted: true };
    }
    if (entity.attemptCount >= 3) return { admitted: false };

    entity.attemptCount += 1;
    await repository.save(entity);
    return { admitted: true };
  }
}
