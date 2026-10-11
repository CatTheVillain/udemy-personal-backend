import { RegistrationThrottle } from '../../../domain/identity.types';
import { RegistrationThrottleEntity } from '../entities/registration-throttle.entity';

export class RegistrationThrottlePersistenceMapper {
  public static toDomain(entity: RegistrationThrottleEntity): RegistrationThrottle {
    return {
      id: entity.id,
      keyHash: entity.keyHash,
      windowStartedAt: entity.windowStartedAt,
      expiresAt: entity.expiresAt,
      attemptCount: entity.attemptCount,
    };
  }

  public static toEntity(throttle: RegistrationThrottle): RegistrationThrottleEntity {
    const entity = new RegistrationThrottleEntity();
    entity.id = throttle.id;
    entity.keyHash = throttle.keyHash;
    entity.windowStartedAt = throttle.windowStartedAt;
    entity.expiresAt = throttle.expiresAt;
    entity.attemptCount = throttle.attemptCount;
    return entity;
  }
}
