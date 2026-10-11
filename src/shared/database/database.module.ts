import { Module } from '@nestjs/common';
import { TypeOrmModule, TypeOrmModuleOptions } from '@nestjs/typeorm';

import { IdentityDatabaseConfig } from './identity-database.config';
import { createNestIdentityDatabaseOptions } from './identity-database-options';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      useFactory: (): TypeOrmModuleOptions =>
        createNestIdentityDatabaseOptions(IdentityDatabaseConfig.from(process.env)),
    }),
  ],
})
export class DatabaseModule {}
