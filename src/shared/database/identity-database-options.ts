import { DataSource, DataSourceOptions } from 'typeorm';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';

import { SessionEntity } from '../../modules/identity/infrastructure/persistence/entities/session.entity';
import { LoginThrottleEntity } from '../../modules/identity/infrastructure/persistence/entities/login-throttle.entity';
import { RegistrationThrottleEntity } from '../../modules/identity/infrastructure/persistence/entities/registration-throttle.entity';
import { UserEntity } from '../../modules/identity/infrastructure/persistence/entities/user.entity';
import { InitialIdentityPersistence1760194800000 } from '../../migrations/1760194800000-initial-identity-persistence';
import { AddIdentityPersistenceInvariants1760194800001 } from '../../migrations/1760194800001-add-identity-persistence-invariants';
import { AddIdentityThrottleKeyOwners1760270400000 } from '../../migrations/1760270400000-add-identity-throttle-key-owners';

const POSTGRES_IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

export interface IdentityDatabaseOptions {
  readonly host: string;
  readonly port: number;
  readonly username: string;
  readonly password: string;
  readonly database: string;
  readonly schema: string;
}

export function createIdentityDatabaseOptions(options: IdentityDatabaseOptions): DataSourceOptions {
  assertSafePostgresIdentifier(options.schema);

  return {
    type: 'postgres',
    host: options.host,
    port: options.port,
    username: options.username,
    password: options.password,
    database: options.database,
    schema: options.schema,
    synchronize: false,
    entities: [UserEntity, SessionEntity, RegistrationThrottleEntity, LoginThrottleEntity],
    migrations: [
      InitialIdentityPersistence1760194800000,
      AddIdentityPersistenceInvariants1760194800001,
      AddIdentityThrottleKeyOwners1760270400000,
    ],
  };
}

export function createNestIdentityDatabaseOptions(
  options: IdentityDatabaseOptions,
): TypeOrmModuleOptions {
  return {
    ...createIdentityDatabaseOptions(options),
    retryAttempts: 1,
    verboseRetryLog: false,
  };
}

export function createIdentityDataSource(options: IdentityDatabaseOptions): DataSource {
  return new DataSource(createIdentityDatabaseOptions(options));
}

function assertSafePostgresIdentifier(value: string): void {
  if (!POSTGRES_IDENTIFIER.test(value)) {
    throw new Error('Invalid PostgreSQL schema identifier.');
  }
}
