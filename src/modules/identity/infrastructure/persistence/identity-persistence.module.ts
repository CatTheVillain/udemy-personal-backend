import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

import { IDENTITY_TRANSACTION_PORT } from '../../application/ports/identity.ports';
import { LoginThrottleEntity } from './entities/login-throttle.entity';
import { RegistrationThrottleEntity } from './entities/registration-throttle.entity';
import { SessionEntity } from './entities/session.entity';
import { UserEntity } from './entities/user.entity';
import { TypeOrmIdentityTransactionAdapter } from './typeorm-identity-transaction.adapter';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      UserEntity,
      SessionEntity,
      RegistrationThrottleEntity,
      LoginThrottleEntity,
    ]),
  ],
  providers: [
    {
      provide: IDENTITY_TRANSACTION_PORT,
      useFactory: (dataSource: DataSource): TypeOrmIdentityTransactionAdapter =>
        new TypeOrmIdentityTransactionAdapter(dataSource),
      inject: [DataSource],
    },
  ],
  exports: [IDENTITY_TRANSACTION_PORT],
})
export class IdentityPersistenceModule {}
