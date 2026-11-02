import { Module } from '@nestjs/common';

import { HelloController } from './modules/system/hello/hello.controller';
import { IdentityDatabaseModule } from './modules/identity/infrastructure/persistence/composition/identity-database.module';
import { IdentityPersistenceModule } from './modules/identity/infrastructure/persistence/composition/identity-persistence.module';
import { IdentityAuthModule } from './modules/identity/presentation/http/identity-auth.module';

@Module({
  imports: [IdentityDatabaseModule, IdentityPersistenceModule, IdentityAuthModule],
  controllers: [HelloController],
})
export class AppModule {}
