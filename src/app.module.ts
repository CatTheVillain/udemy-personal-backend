import { Module } from '@nestjs/common';

import { HelloController } from './modules/system/hello/hello.controller';
import { IdentityPersistenceModule } from './modules/identity/infrastructure/persistence/identity-persistence.module';
import { DatabaseModule } from './shared/database/database.module';

@Module({
  imports: [DatabaseModule, IdentityPersistenceModule],
  controllers: [HelloController],
})
export class AppModule {}
