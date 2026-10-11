import { Session } from '../../../domain/identity.types';
import { SessionEntity } from '../entities/session.entity';

export class SessionPersistenceMapper {
  public static toDomain(entity: SessionEntity): Session {
    return {
      id: entity.id,
      userId: entity.userId,
      tokenHash: entity.tokenHash,
      csrfTokenHash: entity.csrfTokenHash,
      state: entity.state,
      createdAt: entity.createdAt,
      lastSeenAt: entity.lastSeenAt,
      absoluteExpiresAt: entity.absoluteExpiresAt,
      idleExpiresAt: entity.idleExpiresAt,
      revokedAt: entity.revokedAt,
    };
  }

  public static toEntity(session: Session): SessionEntity {
    const entity = new SessionEntity();
    entity.id = session.id;
    entity.userId = session.userId;
    entity.tokenHash = session.tokenHash;
    entity.csrfTokenHash = session.csrfTokenHash;
    entity.state = session.state;
    entity.createdAt = session.createdAt;
    entity.lastSeenAt = session.lastSeenAt;
    entity.absoluteExpiresAt = session.absoluteExpiresAt;
    entity.idleExpiresAt = session.idleExpiresAt;
    entity.revokedAt = session.revokedAt;
    return entity;
  }
}
