import { AccessCommandFingerprint } from './access-command-fingerprint';

describe('AccessCommandFingerprint', () => {
  it('normalizes UUID representations while binding the principal and every command field', () => {
    const command = {
      commandId: 'A0B1C2D3-E4F5-4A67-8B90-1234567890AB',
      targetUserId: 'B0B1C2D3-E4F5-4A67-8B90-1234567890AB',
      action: 'grant' as const,
      capability: 'administrator' as const,
      reason: 'bootstrap',
      reference: 'operator-1',
    };
    const principal = { kind: 'bootstrap' as const, binding: 'trusted-server-bootstrap' };

    expect(AccessCommandFingerprint.create(principal, command)).toBe(
      AccessCommandFingerprint.create(principal, {
        ...command,
        commandId: command.commandId.toLowerCase(),
        targetUserId: command.targetUserId.toLowerCase(),
      }),
    );
    expect(AccessCommandFingerprint.create({ ...principal, binding: 'other' }, command)).not.toBe(
      AccessCommandFingerprint.create(principal, command),
    );
  });
});
