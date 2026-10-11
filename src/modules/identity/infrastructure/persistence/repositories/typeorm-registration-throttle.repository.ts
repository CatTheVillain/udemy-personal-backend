import { EntityManager } from 'typeorm';

import { RegistrationThrottleRepositoryPort } from '../../../application/ports/identity.ports';
import { RegistrationThrottle, RegistrationThrottleLookup } from '../../../domain/identity.types';
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
}
