import { Injectable } from '@nestjs/common';

import { AccessAdministrationOutcome } from '../application/access-administration/contracts/access-administration.contracts';
import { IdentityAccessAdministrationService } from '../application/access-administration/services/identity-access-administration.service';
import { ConfigOperatorCredentialVerifier } from '../application/access-administration/services/operator-credential-verifier';
import { OperatorInvocationInput } from './operator-invocation-parser';

@Injectable()
export class AccessAdministrationOperatorEntrypoint {
  public constructor(
    private readonly administration: IdentityAccessAdministrationService,
    private readonly verifier: ConfigOperatorCredentialVerifier,
  ) {}

  public async execute(
    input: OperatorInvocationInput,
    credential: Buffer,
  ): Promise<AccessAdministrationOutcome> {
    const principal = await this.verifier.verify(input.purpose, credential);
    if (principal.kind === 'rejected') return { code: 'access_administration_unauthorized' };
    return this.administration.execute({
      kind: 'operator',
      purpose: input.purpose,
      credential,
      commandId: input.commandId,
      targetUserId: input.targetUserId,
      action: 'grant',
      capability: 'administrator',
      reason: input.reason,
      reference: input.reference,
    });
  }
}
