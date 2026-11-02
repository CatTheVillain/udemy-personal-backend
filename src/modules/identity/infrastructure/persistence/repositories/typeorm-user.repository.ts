import { EntityManager } from 'typeorm';

import { UserRepositoryPort } from '../../../application/interfaces/identity.ports';
import { User } from '../../../domain/identity.types';
import { UserEntity } from '../entities/user.entity';
import { UserPersistenceMapper } from '../mappers/user.persistence-mapper';
import type { Nullable } from '#shared/types/absence.types';

export class TypeOrmUserRepository implements UserRepositoryPort {
  public constructor(private readonly entityManager: EntityManager) {}

  public async findByNormalizedEmail(normalizedEmail: string): Promise<Nullable<User>> {
    const entity = await this.entityManager
      .getRepository(UserEntity)
      .findOneBy({ normalizedEmail });
    return entity === null ? null : UserPersistenceMapper.toDomain(entity);
  }

  public async findById(id: string): Promise<Nullable<User>> {
    const entity = await this.entityManager.getRepository(UserEntity).findOneBy({ id });
    return entity === null ? null : UserPersistenceMapper.toDomain(entity);
  }

  public async findLockedByIds(ids: readonly string[]): Promise<readonly User[]> {
    const distinctIds = [...new Set(ids)].sort();
    if (distinctIds.length === 0) return [];
    const entities = await this.entityManager
      .getRepository(UserEntity)
      .createQueryBuilder('user')
      .setLock('pessimistic_write')
      .where('user.id IN (:...ids)', { ids: distinctIds })
      .orderBy('user.id', 'ASC')
      .getMany();
    return entities.map(UserPersistenceMapper.toDomain);
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
