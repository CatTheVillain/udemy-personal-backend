import { Module } from '@nestjs/common';

import { HelloController } from './modules/system/hello/hello.controller';
import { IdentityPersistenceModule } from './modules/identity/infrastructure/persistence/identity-persistence.module';
import { IdentityAuthModule } from './modules/identity/presentation/identity-auth.module';
import { DatabaseModule } from './shared/database/database.module';

@Module({
  imports: [DatabaseModule, IdentityPersistenceModule, IdentityAuthModule],
  controllers: [HelloController],
})
export class AppModule {}
