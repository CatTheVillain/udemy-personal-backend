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

  public constructor(entityManager: EntityManager) {
    this.users = new TypeOrmUserRepository(entityManager);
    this.sessions = new TypeOrmSessionRepository(entityManager);
    this.registrationThrottles = new TypeOrmRegistrationThrottleRepository(entityManager);
    this.loginThrottles = new TypeOrmLoginThrottleRepository(entityManager);
  }
}
