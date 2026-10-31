import { EntityManager } from 'typeorm';

import {
  AccessAdministrationLockRepositoryPort,
  AccessMembershipLockResult,
} from '../../../application/ports/identity.ports';

const CAPABILITY_ADMINISTRATION_ADVISORY_NAMESPACE = 734_111;
const ADMINISTRATOR_MEMBERSHIP_LOCK = 5;

interface AdvisoryLockRow {
  readonly locked: boolean;
}

export class TypeOrmAccessAdministrationLockRepository implements AccessAdministrationLockRepositoryPort {
  public constructor(private readonly entityManager: EntityManager) {}

  public async tryAcquireAdministratorMembershipLock(): Promise<AccessMembershipLockResult> {
    const rows = await this.entityManager.query<readonly AdvisoryLockRow[]>(
      'SELECT pg_try_advisory_xact_lock($1, $2) AS locked',
      [CAPABILITY_ADMINISTRATION_ADVISORY_NAMESPACE, ADMINISTRATOR_MEMBERSHIP_LOCK],
    );
    return rows[0]?.locked === true ? { kind: 'acquired' } : { kind: 'busy', retryAfterSeconds: 1 };
  }
}
