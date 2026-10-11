import { User } from '../../../domain/identity.types';
import { UserEntity } from '../entities/user.entity';

export class UserPersistenceMapper {
  public static toDomain(entity: UserEntity): User {
    return {
      id: entity.id,
      normalizedEmail: entity.normalizedEmail,
      passwordHash: entity.passwordHash,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
    };
  }

  public static toEntity(user: User): UserEntity {
    const entity = new UserEntity();
    entity.id = user.id;
    entity.normalizedEmail = user.normalizedEmail;
    entity.passwordHash = user.passwordHash;
    entity.createdAt = user.createdAt;
    entity.updatedAt = user.updatedAt;
    return entity;
  }
}
