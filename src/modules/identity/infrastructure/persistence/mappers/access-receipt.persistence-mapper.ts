import { AccessCommandReceipt } from '../../../domain/access-administration.types';
import type { NewAccessCommandReceipt } from '../../../application/interfaces/identity.ports';
import { AccessCommandReceiptEntity } from '../entities/access-command-receipt.entity';

export class AccessReceiptPersistenceMapper {
  public static toPendingEntity(receipt: NewAccessCommandReceipt): AccessCommandReceiptEntity {
    const entity = new AccessCommandReceiptEntity();
    entity.commandId = receipt.commandId;
    entity.principalKind = receipt.principal.kind;
    entity.principalBinding = receipt.principal.binding;
    entity.targetUserId = receipt.targetUserId;
    entity.action = receipt.action;
    entity.capability = receipt.capability;
    entity.reason = receipt.reason;
    entity.reference = receipt.reference;
    entity.semanticFingerprint = receipt.semanticFingerprint;
    entity.state = 'pending';
    entity.outcomeCode = null;
    entity.changeId = null;
    return entity;
  }

  public static toDomain(entity: AccessCommandReceiptEntity): AccessCommandReceipt {
    return {
      commandId: entity.commandId,
      principal: { kind: entity.principalKind, binding: entity.principalBinding },
      targetUserId: entity.targetUserId,
      action: entity.action,
      capability: entity.capability,
      reason: entity.reason,
      reference: entity.reference,
      semanticFingerprint: entity.semanticFingerprint,
      state: entity.state,
      outcomeCode: entity.outcomeCode,
      changeId: entity.changeId,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
    };
  }
}
