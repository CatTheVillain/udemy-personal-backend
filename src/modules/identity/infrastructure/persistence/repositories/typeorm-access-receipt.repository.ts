import { EntityManager, QueryFailedError } from 'typeorm';

import {
  AccessReceiptCompletion,
  AccessReceiptPendingInsertResult,
  AccessReceiptRepositoryPort,
  NewAccessCommandReceipt,
} from '../../../application/ports/identity.ports';
import { AccessCommandReceipt } from '../../../domain/access-administration.types';
import { AccessCommandReceiptEntity } from '../entities/access-command-receipt.entity';
import { AccessReceiptPersistenceMapper } from '../mappers/access-receipt.persistence-mapper';

const COMMAND_RECEIPT_CONSTRAINT = 'uq_identity_access_command_receipts_command_id';

interface PostgresErrorDetails {
  readonly code?: unknown;
  readonly constraint?: unknown;
}

export class TypeOrmAccessReceiptRepository implements AccessReceiptRepositoryPort {
  public constructor(private readonly entityManager: EntityManager) {}

  public async findByCommandId(commandId: string): Promise<AccessCommandReceipt | null> {
    const entity = await this.entityManager
      .getRepository(AccessCommandReceiptEntity)
      .findOneBy({ commandId });
    return entity === null ? null : AccessReceiptPersistenceMapper.toDomain(entity);
  }

  public async insertPending(
    receipt: NewAccessCommandReceipt,
  ): Promise<AccessReceiptPendingInsertResult> {
    try {
      await this.entityManager
        .getRepository(AccessCommandReceiptEntity)
        .insert(AccessReceiptPersistenceMapper.toPendingEntity(receipt));
      return { kind: 'inserted' };
    } catch (error: unknown) {
      if (isCommandReceiptCollision(error)) return { kind: 'command_id_collision' };
      throw error;
    }
  }

  public async complete(commandId: string, completion: AccessReceiptCompletion): Promise<void> {
    const result = await this.entityManager.getRepository(AccessCommandReceiptEntity).update(
      { commandId, state: 'pending' },
      {
        state: 'completed',
        outcomeCode: completion.outcomeCode,
        changeId: completion.changeId,
      },
    );
    if (result.affected !== 1) throw new Error('Unable to complete access command receipt.');
  }
}

function isCommandReceiptCollision(error: unknown): boolean {
  if (!(error instanceof QueryFailedError)) return false;
  const details = error.driverError as PostgresErrorDetails;
  return details.code === '23505' && details.constraint === COMMAND_RECEIPT_CONSTRAINT;
}
