import { Module } from '@nestjs/common';

import { IdentityAccessAdministrationCredentialsConfig } from '../application/access-administration-config';
import { OPERATOR_CREDENTIAL_VERIFIER_PORT } from '../application/access-administration.types';
import { IdentityAccessAdministrationService } from '../application/identity-access-administration.service';
import { ConfigOperatorCredentialVerifier } from '../application/operator-credential-verifier';
import { IdentityPersistenceModule } from '../infrastructure/persistence/identity-persistence.module';
import { DatabaseModule } from '../../../shared/database/database.module';
import { AccessAdministrationOperatorEntrypoint } from './access-administration-operator.service';

@Module({
  imports: [DatabaseModule, IdentityPersistenceModule],
  providers: [
    IdentityAccessAdministrationService,
    AccessAdministrationOperatorEntrypoint,
    {
      provide: ConfigOperatorCredentialVerifier,
      useFactory: (): ConfigOperatorCredentialVerifier =>
        new ConfigOperatorCredentialVerifier(
          IdentityAccessAdministrationCredentialsConfig.from(process.env),
        ),
    },
    {
      provide: OPERATOR_CREDENTIAL_VERIFIER_PORT,
      useExisting: ConfigOperatorCredentialVerifier,
    },
  ],
  exports: [AccessAdministrationOperatorEntrypoint],
})
export class AccessAdministrationOperatorAppModule {}
