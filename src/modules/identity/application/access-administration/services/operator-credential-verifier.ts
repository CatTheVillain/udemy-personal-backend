import { OnModuleDestroy } from '@nestjs/common';

import {
  OperatorCredentialVerifierPort,
  OperatorCredentialVerificationResult,
} from '../contracts/access-administration.contracts';
import {
  IdentityAccessAdministrationCredentialsConfig,
  OperatorCredentialPurpose,
} from '../config/access-administration-config';

export class ConfigOperatorCredentialVerifier
  implements OperatorCredentialVerifierPort, OnModuleDestroy
{
  public constructor(private readonly config: IdentityAccessAdministrationCredentialsConfig) {}

  public async verify(
    purpose: OperatorCredentialPurpose,
    credential: Buffer,
  ): Promise<OperatorCredentialVerificationResult> {
    if (!this.config.matches(purpose, credential)) return { kind: 'rejected' };
    return { kind: purpose, binding: `trusted-server-${purpose}` };
  }

  public onModuleDestroy(): void {
    this.config.destroy();
  }
}
