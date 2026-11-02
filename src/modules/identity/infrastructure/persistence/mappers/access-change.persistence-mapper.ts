import { AccessChange } from '../../../domain/access-administration.types';
import type { NewAccessChange } from '../../../application/interfaces/identity.ports';
import { AccessChangeEntity } from '../entities/access-change.entity';

export class AccessChangePersistenceMapper {
  public static toEntity(change: NewAccessChange): AccessChangeEntity {
    const entity = new AccessChangeEntity();
    entity.commandId = change.commandId;
    entity.targetUserId = change.targetUserId;
    entity.principalKind = change.principal.kind;
    entity.principalBinding = change.principal.binding;
    entity.action = change.action;
    entity.capability = change.capability;
    entity.beforeActive = change.beforeActive;
    entity.afterActive = change.afterActive;
    entity.reason = change.reason;
    entity.reference = change.reference;
    return entity;
  }

  public static toDomain(entity: AccessChangeEntity): AccessChange {
    return {
      id: entity.id,
      commandId: entity.commandId,
      targetUserId: entity.targetUserId,
      principal: { kind: entity.principalKind, binding: entity.principalBinding },
      action: entity.action,
      capability: entity.capability,
      beforeActive: entity.beforeActive,
      afterActive: entity.afterActive,
      reason: entity.reason,
      reference: entity.reference,
      createdAt: entity.createdAt,
    };
  }
}
