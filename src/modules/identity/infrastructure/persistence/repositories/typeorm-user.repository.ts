import { EntityManager } from 'typeorm';

import { UserRepositoryPort } from '../../../application/ports/identity.ports';
import { User } from '../../../domain/identity.types';
import { UserEntity } from '../entities/user.entity';
import { UserPersistenceMapper } from '../mappers/user.persistence-mapper';

export class TypeOrmUserRepository implements UserRepositoryPort {
  public constructor(private readonly entityManager: EntityManager) {}

  public async findByNormalizedEmail(normalizedEmail: string): Promise<User | null> {
    const entity = await this.entityManager
      .getRepository(UserEntity)
      .findOneBy({ normalizedEmail });
    return entity === null ? null : UserPersistenceMapper.toDomain(entity);
  }

  public async insert(user: User): Promise<void> {
    await this.entityManager.getRepository(UserEntity).insert(UserPersistenceMapper.toEntity(user));
  }
}
