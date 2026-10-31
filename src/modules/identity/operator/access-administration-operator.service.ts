import { Injectable } from '@nestjs/common';

import { IdentityAccessAdministrationService } from '../application/identity-access-administration.service';
import { ConfigOperatorCredentialVerifier } from '../application/operator-credential-verifier';
import { AccessAdministrationOutcome } from '../application/access-administration.types';
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
