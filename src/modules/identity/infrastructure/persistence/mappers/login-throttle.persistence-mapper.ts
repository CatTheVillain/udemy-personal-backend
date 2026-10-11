import { LoginThrottle } from '../../../domain/identity.types';
import { LoginThrottleEntity } from '../entities/login-throttle.entity';

export class LoginThrottlePersistenceMapper {
  public static toDomain(entity: LoginThrottleEntity): LoginThrottle {
    return {
      id: entity.id,
      keyHash: entity.keyHash,
      windowStartedAt: entity.windowStartedAt,
      expiresAt: entity.expiresAt,
      failureCount: entity.failureCount,
    };
  }

  public static toEntity(throttle: LoginThrottle): LoginThrottleEntity {
    const entity = new LoginThrottleEntity();
    entity.id = throttle.id;
    entity.keyHash = throttle.keyHash;
    entity.windowStartedAt = throttle.windowStartedAt;
    entity.expiresAt = throttle.expiresAt;
    entity.failureCount = throttle.failureCount;
    return entity;
  }
}
