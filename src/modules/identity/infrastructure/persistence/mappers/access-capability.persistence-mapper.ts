import {
  AccessCapability,
  AccessCapabilityProjectionRead,
  AccessCapabilityRecord,
} from '../../../domain/access-administration.types';
import { AccessCapabilityEntity } from '../entities/access-capability.entity';

export class AccessCapabilityPersistenceMapper {
  public static toDomain(entity: AccessCapabilityEntity): AccessCapabilityRecord {
    return {
      id: entity.id,
      userId: entity.userId,
      capability: entity.capability,
      active: entity.active,
      createdAt: entity.createdAt,
    };
  }

  public static toActiveProjection(rows: unknown): AccessCapabilityProjectionRead {
    if (!Array.isArray(rows)) return { kind: 'unavailable' };
    const capabilities = new Set<AccessCapability>();
    for (const row of rows) {
      const capability = readRawCapability(row);
      if (capability === null) return { kind: 'unavailable' };
      capabilities.add(capability);
    }
    return {
      kind: 'available',
      projection: { capabilities: [...capabilities].sort() },
    };
  }
}

function readRawCapability(row: unknown): AccessCapability | null {
  if (!isRecord(row)) return null;
  const capability = row.capability;
  if (
    capability !== 'instructor' &&
    capability !== 'content_moderator' &&
    capability !== 'administrator'
  ) {
    return null;
  }
  return capability;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
