import {
  OperatorInvocationInvalidError,
  OperatorInvocationParser,
} from './operator-invocation-parser';

const TARGET_USER_ID = 'A0B1C2D3-E4F5-4A67-8B90-1234567890AB';
const COMMAND_ID = 'B0B1C2D3-E4F5-4A67-8B90-1234567890AB';

describe('OperatorInvocationParser', () => {
  it('normalizes UUIDs and rejects repeated or positional arguments', () => {
    const parser = new OperatorInvocationParser();
    expect(parser.parse(validArguments())).toEqual({
      purpose: 'bootstrap',
      targetUserId: TARGET_USER_ID.toLowerCase(),
      commandId: COMMAND_ID.toLowerCase(),
      reason: 'bootstrap administrator',
      reference: 'incident-1',
    });
    expect(() => parser.parse([...validArguments(), '--purpose', 'recovery'])).toThrow(
      OperatorInvocationInvalidError,
    );
    expect(() => parser.parse([...validArguments(), 'unexpected'])).toThrow(
      OperatorInvocationInvalidError,
    );
  });
});

function validArguments(): readonly string[] {
  return [
    '--purpose',
    'bootstrap',
    '--target-user-id',
    TARGET_USER_ID,
    '--command-id',
    COMMAND_ID,
    '--reason',
    'bootstrap administrator',
    '--reference',
    'incident-1',
    '--credential-env',
    'IDENTITY_ACCESS_OPERATOR_CREDENTIAL',
  ];
}
