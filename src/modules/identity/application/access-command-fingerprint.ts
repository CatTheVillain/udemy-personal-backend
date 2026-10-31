import { createHash } from 'node:crypto';

import { AccessPrincipal } from '../domain/access-administration.types';
import { AccessCommandDetails } from './access-administration.types';

const FINGERPRINT_VERSION = 'access-command-v1';

export class AccessCommandFingerprint {
  public static create(principal: AccessPrincipal, command: AccessCommandDetails): string {
    const canonical = JSON.stringify([
      FINGERPRINT_VERSION,
      principal.kind,
      principal.binding,
      normalizeUuid(command.commandId),
      normalizeUuid(command.targetUserId),
      command.action,
      command.capability,
      command.reason,
      command.reference,
    ]);
    return createHash('sha256').update(canonical, 'utf8').digest('hex');
  }
}

function normalizeUuid(value: string): string {
  return value.toLowerCase();
}
