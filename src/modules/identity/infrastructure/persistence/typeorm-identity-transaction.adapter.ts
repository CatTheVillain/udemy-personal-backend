import { DataSource, EntityManager } from 'typeorm';

import {
  IdentityTransactionPort,
  IdentityTransactionScope,
  IdentityTransactionWork,
} from '../../application/ports/identity.ports';
import { TypeOrmLoginThrottleRepository } from './repositories/typeorm-login-throttle.repository';
import { TypeOrmRegistrationThrottleRepository } from './repositories/typeorm-registration-throttle.repository';
import { TypeOrmSessionRepository } from './repositories/typeorm-session.repository';
import { TypeOrmUserRepository } from './repositories/typeorm-user.repository';
import { TypeOrmAccessAdministrationLockRepository } from './repositories/typeorm-access-administration-lock.repository';
import { TypeOrmAccessCapabilityRepository } from './repositories/typeorm-access-capability.repository';
import { TypeOrmAccessChangeRepository } from './repositories/typeorm-access-change.repository';
import { TypeOrmAccessReceiptRepository } from './repositories/typeorm-access-receipt.repository';

export class TypeOrmIdentityTransactionAdapter implements IdentityTransactionPort {
  public constructor(private readonly dataSource: DataSource) {}

  public async run<Result>(work: IdentityTransactionWork<Result>): Promise<Result> {
    return this.dataSource.transaction(async (entityManager: EntityManager): Promise<Result> =>
      work.execute(new TypeOrmIdentityTransactionScope(entityManager)),
    );
  }
}

class TypeOrmIdentityTransactionScope implements IdentityTransactionScope {
  public readonly users: TypeOrmUserRepository;
  public readonly sessions: TypeOrmSessionRepository;
  public readonly registrationThrottles: TypeOrmRegistrationThrottleRepository;
  public readonly loginThrottles: TypeOrmLoginThrottleRepository;
  public readonly accessAdministrationLocks: TypeOrmAccessAdministrationLockRepository;
  public readonly accessCapabilities: TypeOrmAccessCapabilityRepository;
  public readonly accessChanges: TypeOrmAccessChangeRepository;
  public readonly accessReceipts: TypeOrmAccessReceiptRepository;

  public constructor(entityManager: EntityManager) {
    this.users = new TypeOrmUserRepository(entityManager);
    this.sessions = new TypeOrmSessionRepository(entityManager);
    this.registrationThrottles = new TypeOrmRegistrationThrottleRepository(entityManager);
    this.loginThrottles = new TypeOrmLoginThrottleRepository(entityManager);
    this.accessAdministrationLocks = new TypeOrmAccessAdministrationLockRepository(entityManager);
    this.accessCapabilities = new TypeOrmAccessCapabilityRepository(entityManager);
    this.accessChanges = new TypeOrmAccessChangeRepository(entityManager);
    this.accessReceipts = new TypeOrmAccessReceiptRepository(entityManager);
  }
}
