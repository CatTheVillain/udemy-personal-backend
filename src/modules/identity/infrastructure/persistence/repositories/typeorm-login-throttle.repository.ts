import { EntityManager } from 'typeorm';

import { LoginThrottleRepositoryPort } from '../../../application/ports/identity.ports';
import { LoginThrottle, LoginThrottleLookup } from '../../../domain/identity.types';
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
}
