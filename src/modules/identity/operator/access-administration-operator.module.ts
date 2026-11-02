import { Module } from '@nestjs/common';

import { IdentityAccessAdministrationCredentialsConfig } from '../application/access-administration/config/access-administration-config';
import { OPERATOR_CREDENTIAL_VERIFIER_PORT } from '../application/access-administration/contracts/access-administration.contracts';
import { IdentityAccessAdministrationService } from '../application/access-administration/services/identity-access-administration.service';
import { ConfigOperatorCredentialVerifier } from '../application/access-administration/services/operator-credential-verifier';
import { IdentityDatabaseModule } from '../infrastructure/persistence/composition/identity-database.module';
import { IdentityPersistenceModule } from '../infrastructure/persistence/composition/identity-persistence.module';
import { AccessAdministrationOperatorEntrypoint } from './access-administration-operator.service';

@Module({
  imports: [IdentityDatabaseModule, IdentityPersistenceModule],
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
