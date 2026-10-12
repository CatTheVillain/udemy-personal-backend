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

  public async insertIfAbsent(user: User): Promise<boolean> {
    const result = await this.entityManager
      .getRepository(UserEntity)
      .createQueryBuilder()
      .insert()
      .into(UserEntity)
      .values(UserPersistenceMapper.toEntity(user))
      .orIgnore()
      .returning('id')
      .execute();
    return readInsertedRow(result.raw);
  }
}

function readInsertedRow(raw: unknown): boolean {
  if (!Array.isArray(raw)) throw new Error('Unexpected user insert result.');
  if (raw.length === 0) return false;
  if (raw.length !== 1) throw new Error('Unexpected user insert result.');
  const row = raw[0];
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    throw new Error('Unexpected user insert result.');
  }
  const id = Object.entries(row).find(([key]) => key === 'id')?.[1];
  if (typeof id !== 'string') throw new Error('Unexpected user insert result.');
  return true;
}
