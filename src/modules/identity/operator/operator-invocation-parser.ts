import { parseArgs } from 'node:util';

import { OperatorCredentialPurpose } from '../application/access-administration/config/access-administration-config';

export interface OperatorInvocationInput {
  readonly purpose: OperatorCredentialPurpose;
  readonly targetUserId: string;
  readonly commandId: string;
  readonly reason: string;
  readonly reference: string;
}

export class OperatorInvocationInvalidError extends Error {
  public constructor() {
    super('access_administration_invocation_invalid');
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_TEXT = /^[^\x00-\x1f\x7f]{1,512}$/;
const OPTION_NAMES = new Set([
  'purpose',
  'target-user-id',
  'command-id',
  'reason',
  'reference',
  'credential-env',
]);

export class OperatorInvocationParser {
  public parse(argv: readonly string[]): OperatorInvocationInput {
    rejectRepeatedOrUnknownOptions(argv);
    let values: Record<string, string | boolean | undefined>;
    try {
      values = parseArgs({
        args: argv,
        strict: true,
        allowPositionals: false,
        options: {
          purpose: { type: 'string' },
          'target-user-id': { type: 'string' },
          'command-id': { type: 'string' },
          reason: { type: 'string' },
          reference: { type: 'string' },
          'credential-env': { type: 'string' },
        },
      }).values;
    } catch {
      throw new OperatorInvocationInvalidError();
    }
    const purpose = values.purpose;
    const targetUserId = values['target-user-id'];
    const commandId = values['command-id'];
    const reason = values.reason;
    const reference = values.reference;
    if (
      (purpose !== 'bootstrap' && purpose !== 'recovery') ||
      typeof targetUserId !== 'string' ||
      typeof commandId !== 'string' ||
      typeof reason !== 'string' ||
      typeof reference !== 'string' ||
      values['credential-env'] !== 'IDENTITY_ACCESS_OPERATOR_CREDENTIAL' ||
      !UUID.test(targetUserId) ||
      !UUID.test(commandId) ||
      !SAFE_TEXT.test(reason) ||
      !SAFE_TEXT.test(reference)
    ) {
      throw new OperatorInvocationInvalidError();
    }
    return {
      purpose,
      targetUserId: targetUserId.toLowerCase(),
      commandId: commandId.toLowerCase(),
      reason,
      reference,
    };
  }
}

function rejectRepeatedOrUnknownOptions(argv: readonly string[]): void {
  const seen = new Set<string>();
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === undefined) throw new OperatorInvocationInvalidError();
    if (!argument.startsWith('--')) throw new OperatorInvocationInvalidError();
    const option = argument.slice(2).split('=', 1)[0];
    if (option === undefined || !OPTION_NAMES.has(option) || seen.has(option)) {
      throw new OperatorInvocationInvalidError();
    }
    seen.add(option);
    if (!argument.includes('=')) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith('--')) throw new OperatorInvocationInvalidError();
      index += 1;
    }
  }
}
