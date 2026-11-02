import { EntityManager } from 'typeorm';

import type {
  AccessChangeRepositoryPort,
  NewAccessChange,
} from '../../../application/interfaces/identity.ports';
import { AccessChange } from '../../../domain/access-administration.types';
import { AccessChangeEntity } from '../entities/access-change.entity';
import { AccessChangePersistenceMapper } from '../mappers/access-change.persistence-mapper';

export class TypeOrmAccessChangeRepository implements AccessChangeRepositoryPort {
  public constructor(private readonly entityManager: EntityManager) {}

  public async insert(change: NewAccessChange): Promise<AccessChange> {
    const entity = AccessChangePersistenceMapper.toEntity(change);
    return AccessChangePersistenceMapper.toDomain(
      await this.entityManager.getRepository(AccessChangeEntity).save(entity),
    );
  }
}
