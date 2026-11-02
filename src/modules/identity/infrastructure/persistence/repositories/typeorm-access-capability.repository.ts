import { EntityManager } from 'typeorm';

import type { AccessCapabilityRepositoryPort } from '../../../application/interfaces/identity.ports';
import {
  AccessCapability,
  AccessCapabilityProjectionRead,
  AccessCapabilityRecord,
  AccessTransition,
} from '../../../domain/access-administration.types';
import { AccessCapabilityEntity } from '../entities/access-capability.entity';
import { AccessCapabilityPersistenceMapper } from '../mappers/access-capability.persistence-mapper';
import type { Nullable } from '#shared/types/absence.types';

export class TypeOrmAccessCapabilityRepository implements AccessCapabilityRepositoryPort {
  public constructor(private readonly entityManager: EntityManager) {}

  public async findActiveProjectionForUser(
    userId: string,
  ): Promise<AccessCapabilityProjectionRead> {
    try {
      const rows = await this.entityManager
        .getRepository(AccessCapabilityEntity)
        .createQueryBuilder('capability')
        .select('capability.capability', 'capability')
        .where('capability.user_id = :userId', { userId })
        .andWhere('capability.active = true')
        .orderBy('capability.capability', 'ASC')
        .getRawMany();
      return AccessCapabilityPersistenceMapper.toActiveProjection(rows);
    } catch {
      return { kind: 'unavailable' };
    }
  }

  public async findActiveLocked(
    userId: string,
    capability: AccessCapability,
  ): Promise<Nullable<AccessCapabilityRecord>> {
    const entity = await this.entityManager.getRepository(AccessCapabilityEntity).findOne({
      where: { userId, capability, active: true },
      lock: { mode: 'pessimistic_write' },
    });
    return entity === null ? null : AccessCapabilityPersistenceMapper.toDomain(entity);
  }

  public async hasActiveLocked(userId: string, capability: AccessCapability): Promise<boolean> {
    return (await this.findActiveLocked(userId, capability)) !== null;
  }

  public async lockActiveAdministratorsAndCount(): Promise<number> {
    const entities = await this.entityManager
      .getRepository(AccessCapabilityEntity)
      .createQueryBuilder('capability')
      .setLock('pessimistic_write')
      .where('capability.capability = :capability', { capability: 'administrator' })
      .andWhere('capability.active = true')
      .orderBy('capability.id', 'ASC')
      .getMany();
    return entities.length;
  }

  public async applyTransition(
    transition: AccessTransition,
  ): Promise<Nullable<AccessCapabilityRecord>> {
    const repository = this.entityManager.getRepository(AccessCapabilityEntity);
    const active = await this.findActiveLocked(transition.userId, transition.capability);
    if (transition.action === 'grant') {
      if (active !== null) return active;
      const entity = repository.create({
        userId: transition.userId,
        capability: transition.capability,
        active: true,
      });
      return AccessCapabilityPersistenceMapper.toDomain(await repository.save(entity));
    }
    if (active === null) return null;
    await repository.update({ id: active.id }, { active: false });
    return null;
  }
}
