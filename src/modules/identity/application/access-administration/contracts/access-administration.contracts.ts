import { OperatorCredentialPurpose } from '../config/access-administration-config';
import {
  AccessAction,
  AccessCapability,
  AccessPrincipal,
} from '../../../domain/access-administration.types';

export interface AccessCommandDetails {
  readonly commandId: string;
  readonly targetUserId: string;
  readonly action: AccessAction;
  readonly capability: AccessCapability;
  readonly reason: string;
  readonly reference: string;
}

export interface OperatorAccessAdministrationCommand extends AccessCommandDetails {
  readonly kind: 'operator';
  readonly purpose: OperatorCredentialPurpose;
  readonly credential: Buffer;
}

export interface AuthenticatedAdministratorCommand extends AccessCommandDetails {
  readonly kind: 'administrator';
  readonly actorSessionId: string;
  readonly actorTokenHash: string;
}

export type AccessAdministrationCommand =
  OperatorAccessAdministrationCommand | AuthenticatedAdministratorCommand;

export interface AccessReceiptReadRequest {
  readonly command: AccessAdministrationCommand;
}

export type AccessAdministrationOutcome =
  | { readonly code: 'access_administration_completed' }
  | { readonly code: 'access_administration_busy'; readonly retryAfterSeconds: 1 }
  | { readonly code: 'access_administration_unauthorized' }
  | { readonly code: 'access_administration_forbidden' }
  | { readonly code: 'access_administration_conflict' }
  | { readonly code: 'access_administration_unavailable' };

export interface VerifiedOperatorPrincipal extends AccessPrincipal {
  readonly kind: OperatorCredentialPurpose;
}

export type OperatorCredentialVerificationResult =
  VerifiedOperatorPrincipal | { readonly kind: 'rejected' };

export interface OperatorCredentialVerifierPort {
  verify(
    purpose: OperatorCredentialPurpose,
    credential: Buffer,
  ): Promise<OperatorCredentialVerificationResult>;
}

export const OPERATOR_CREDENTIAL_VERIFIER_PORT = Symbol('OperatorCredentialVerifierPort');
