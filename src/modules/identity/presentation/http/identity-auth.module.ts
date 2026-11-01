import { Module } from '@nestjs/common';

import { IdentityAuthConfig } from '../../application/authentication/config/identity-auth.config';
import { IdentityAuthenticationService } from '../../application/authentication/services/identity-authentication.service';
import { IDENTITY_CLOCK } from '../../application/authentication/contracts/identity-clock.contracts';
import { SystemIdentityClock } from '../../application/authentication/services/identity-clock';
import { ScryptPasswordHasher } from '../../application/credentials/services/password-hasher';
import { IdentityPersistenceModule } from '../../infrastructure/persistence/identity-persistence.module';
import { IdentityAuthController } from './controllers/identity-auth.controller';
import { AuthenticatedCsrfGuard } from './guards/authenticated-csrf.guard';
import { PreAuthCsrfGuard } from './guards/pre-auth-csrf.guard';

@Module({
  imports: [IdentityPersistenceModule],
  controllers: [IdentityAuthController],
  providers: [
    IdentityAuthenticationService,
    AuthenticatedCsrfGuard,
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
