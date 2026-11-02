import { Inject, Injectable } from '@nestjs/common';

import {
  AccessCommandReceipt,
  AccessPrincipal,
  AccessTransition,
} from '../../../domain/access-administration.types';
import { AccessCommandFingerprint } from '../helpers/access-command-fingerprint';
import {
  AccessAdministrationCommand,
  AccessAdministrationOutcome,
  AccessReceiptReadRequest,
  OPERATOR_CREDENTIAL_VERIFIER_PORT,
  OperatorCredentialVerifierPort,
} from '../contracts/access-administration.contracts';
import {
  AccessAuthorizationResult,
  AccessReceiptLookupResult,
} from '../contracts/access-administration-service.contracts';
import {
  IDENTITY_TRANSACTION_PORT,
  IdentityTransactionPort,
  IdentityTransactionScope,
} from '../../interfaces/identity.ports';

@Injectable()
export class IdentityAccessAdministrationService {
  public constructor(
    @Inject(IDENTITY_TRANSACTION_PORT) private readonly transactions: IdentityTransactionPort,
    @Inject(OPERATOR_CREDENTIAL_VERIFIER_PORT)
    private readonly operatorCredentialVerifier: OperatorCredentialVerifierPort,
  ) {}

  public async execute(command: AccessAdministrationCommand): Promise<AccessAdministrationOutcome> {
    try {
      return await this.transactions.run({
        execute: (scope) => this.executeInTransaction(scope, command),
      });
    } catch (error: unknown) {
      if (error instanceof AccessReceiptCollision) {
        try {
          return await this.transactions.run({
            execute: (scope) => this.reloadAfterReceiptCollision(scope, command),
          });
        } catch {
          return { code: 'access_administration_unavailable' };
        }
      }
      return { code: 'access_administration_unavailable' };
    }
  }

  public async readReceipt(
    request: AccessReceiptReadRequest,
  ): Promise<AccessAdministrationOutcome> {
    try {
      return await this.transactions.run({
        execute: async (scope) => {
          const authorization = await this.authorize(scope, request.command, false);
          if ('outcome' in authorization) return authorization.outcome;
          return (
            await this.lookupAuthorizedReceipt(scope, request.command, authorization.principal)
          ).outcome;
        },
      });
    } catch {
      return { code: 'access_administration_unavailable' };
    }
  }

  private async executeInTransaction(
    scope: IdentityTransactionScope,
    command: AccessAdministrationCommand,
  ): Promise<AccessAdministrationOutcome> {
    const authorization = await this.authorize(
      scope,
      command,
      isAdministratorMembershipCommand(command),
    );
    if ('outcome' in authorization) return authorization.outcome;

    const receiptLookup = await this.lookupAuthorizedReceipt(
      scope,
      command,
      authorization.principal,
    );
    if (receiptLookup.kind !== 'absent') return receiptLookup.outcome;

    if (
      command.action === 'grant' &&
      (command.capability === 'instructor' || command.capability === 'content_moderator') &&
      (await scope.accessCapabilities.hasActiveLocked(
        command.targetUserId,
        command.capability === 'instructor' ? 'content_moderator' : 'instructor',
      ))
    ) {
      return { code: 'access_administration_conflict' };
    }

    const current = await scope.accessCapabilities.findActiveLocked(
      command.targetUserId,
      command.capability,
    );
    const administratorCount =
      command.capability === 'administrator'
        ? await scope.accessCapabilities.lockActiveAdministratorsAndCount()
        : null;
    if (command.kind === 'operator' && administratorCount !== 0) {
      return { code: 'access_administration_forbidden' };
    }
    if (command.action === 'revoke' && current !== null && administratorCount !== null) {
      if (administratorCount <= 1) return { code: 'access_administration_forbidden' };
    }

    const fingerprint = AccessCommandFingerprint.create(authorization.principal, command);
    const pending = await scope.accessReceipts.insertPending({
      commandId: command.commandId,
      principal: authorization.principal,
      targetUserId: command.targetUserId,
      action: command.action,
      capability: command.capability,
      reason: command.reason,
      reference: command.reference,
      semanticFingerprint: fingerprint,
    });
    if (pending.kind === 'command_id_collision') throw new AccessReceiptCollision();

    const transition: AccessTransition = {
      userId: command.targetUserId,
      capability: command.capability,
      action: command.action,
      beforeActive: current !== null,
      afterActive: command.action === 'grant',
    };
    await scope.accessCapabilities.applyTransition(transition);
    const change = await scope.accessChanges.insert({
      commandId: command.commandId,
      targetUserId: command.targetUserId,
      principal: authorization.principal,
      action: command.action,
      capability: command.capability,
      beforeActive: transition.beforeActive,
      afterActive: transition.afterActive,
      reason: command.reason,
      reference: command.reference,
    });
    await scope.accessReceipts.complete(command.commandId, {
      outcomeCode: 'access_administration_completed',
      changeId: change.id,
    });
    return { code: 'access_administration_completed' };
  }

  private async reloadAfterReceiptCollision(
    scope: IdentityTransactionScope,
    command: AccessAdministrationCommand,
  ): Promise<AccessAdministrationOutcome> {
    const authorization = await this.authorize(
      scope,
      command,
      isAdministratorMembershipCommand(command),
    );
    if ('outcome' in authorization) return authorization.outcome;
    return (await this.lookupAuthorizedReceipt(scope, command, authorization.principal)).outcome;
  }

  private async authorize(
    scope: IdentityTransactionScope,
    command: AccessAdministrationCommand,
    requiresMembershipLock: boolean,
  ): Promise<AccessAuthorizationResult> {
    const preliminaryActorId =
      command.kind === 'administrator'
        ? ((await scope.sessions.findById(command.actorSessionId))?.userId ?? null)
        : null;
    if (command.kind === 'administrator' && preliminaryActorId === null) {
      return { outcome: { code: 'access_administration_unauthorized' } };
    }
    if (requiresMembershipLock) {
      const lock = await scope.accessAdministrationLocks.tryAcquireAdministratorMembershipLock();
      if (lock.kind === 'busy') {
        return { outcome: { code: 'access_administration_busy', retryAfterSeconds: 1 } };
      }
    }
    const userIds =
      preliminaryActorId === null
        ? [command.targetUserId]
        : [preliminaryActorId, command.targetUserId];
    const users = await scope.users.findLockedByIds(userIds);
    if (users.length !== new Set(userIds).size) {
      return { outcome: { code: 'access_administration_forbidden' } };
    }
    if (command.kind === 'operator') return this.authorizeOperator(command);
    if (preliminaryActorId === null) {
      return { outcome: { code: 'access_administration_unauthorized' } };
    }
    const session = await scope.sessions.findAccessAdministrationCurrentLockedAuthenticated(
      command.actorSessionId,
      command.actorTokenHash,
    );
    if (session === null || session.userId !== preliminaryActorId) {
      return { outcome: { code: 'access_administration_unauthorized' } };
    }
    const isAdministrator = await scope.accessCapabilities.hasActiveLocked(
      preliminaryActorId,
      'administrator',
    );
    if (!isAdministrator) return { outcome: { code: 'access_administration_forbidden' } };
    return { principal: { kind: 'administrator', binding: `session:${session.id}` } };
  }

  private async authorizeOperator(
    command: AccessAdministrationCommand,
  ): Promise<AccessAuthorizationResult> {
    if (
      command.kind !== 'operator' ||
      command.action !== 'grant' ||
      command.capability !== 'administrator'
    ) {
      return { outcome: { code: 'access_administration_forbidden' } };
    }
    const principal = await this.operatorCredentialVerifier.verify(
      command.purpose,
      command.credential,
    );
    if (principal.kind === 'rejected')
      return { outcome: { code: 'access_administration_unauthorized' } };
    return { principal };
  }

  private async lookupAuthorizedReceipt(
    scope: IdentityTransactionScope,
    command: AccessAdministrationCommand,
    principal: AccessPrincipal,
  ): Promise<AccessReceiptLookupResult> {
    const receipt = await scope.accessReceipts.findByCommandId(command.commandId);
    if (receipt === null) {
      return { kind: 'absent', outcome: { code: 'access_administration_unavailable' } };
    }
    const fingerprint = AccessCommandFingerprint.create(principal, command);
    if (!matchesReceipt(receipt, principal, fingerprint)) {
      return { kind: 'present', outcome: { code: 'access_administration_conflict' } };
    }
    if (receipt.state !== 'completed' || receipt.outcomeCode === null) {
      return { kind: 'present', outcome: { code: 'access_administration_unavailable' } };
    }
    return { kind: 'present', outcome: toOutcome(receipt.outcomeCode) };
  }
}

class AccessReceiptCollision extends Error {}

function isAdministratorMembershipCommand(command: AccessAdministrationCommand): boolean {
  return command.capability === 'administrator';
}

function matchesReceipt(
  receipt: AccessCommandReceipt,
  principal: AccessPrincipal,
  fingerprint: string,
): boolean {
  return (
    receipt.principal.kind === principal.kind &&
    receipt.principal.binding === principal.binding &&
    receipt.semanticFingerprint === fingerprint
  );
}

function toOutcome(outcomeCode: string): AccessAdministrationOutcome {
  if (outcomeCode === 'access_administration_completed') {
    return { code: 'access_administration_completed' };
  }
  return { code: 'access_administration_unavailable' };
}
