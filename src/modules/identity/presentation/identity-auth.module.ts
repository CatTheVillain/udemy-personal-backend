import { Module } from '@nestjs/common';

import { IdentityAuthenticationService } from '../application/identity-authentication.service';
import { IdentityAuthConfig } from '../application/identity-auth.config';
import { IDENTITY_CLOCK, SystemIdentityClock } from '../application/identity-clock';
import { ScryptPasswordHasher } from '../application/password-hasher';
import { IdentityPersistenceModule } from '../infrastructure/persistence/identity-persistence.module';
import { IdentityAuthController } from './identity-auth.controller';
import { PreAuthCsrfGuard } from './pre-auth-csrf.guard';

@Module({
  imports: [IdentityPersistenceModule],
  controllers: [IdentityAuthController],
  providers: [
    IdentityAuthenticationService,
    PreAuthCsrfGuard,
    ScryptPasswordHasher,
    {
      provide: IdentityAuthConfig,
      useFactory: (): IdentityAuthConfig => IdentityAuthConfig.from(process.env),
    },
    { provide: IDENTITY_CLOCK, useClass: SystemIdentityClock },
  ],
})
export class IdentityAuthModule {}
