export type AccessCapability = 'instructor' | 'content_moderator' | 'administrator';
export type AccessAction = 'grant' | 'revoke';
export type AccessPrincipalKind = 'bootstrap' | 'recovery' | 'administrator';
export type AccessReceiptState = 'pending' | 'completed';

export interface AccessPrincipal {
  readonly kind: AccessPrincipalKind;
  readonly binding: string;
}

export interface AccessCapabilityRecord {
  readonly id: string;
  readonly userId: string;
  readonly capability: AccessCapability;
  readonly active: boolean;
  readonly createdAt: Date;
}

export interface AccessCapabilityProjection {
  readonly capabilities: readonly AccessCapability[];
}

export type AccessCapabilityProjectionRead =
  | { readonly kind: 'available'; readonly projection: AccessCapabilityProjection }
  | { readonly kind: 'unavailable' };

export interface AccessTransition {
  readonly userId: string;
  readonly capability: AccessCapability;
  readonly action: AccessAction;
  readonly beforeActive: boolean;
  readonly afterActive: boolean;
}

export interface AccessChange {
  readonly id: string;
  readonly commandId: string;
  readonly targetUserId: string;
  readonly principal: AccessPrincipal;
  readonly action: AccessAction;
  readonly capability: AccessCapability;
  readonly beforeActive: boolean;
  readonly afterActive: boolean;
  readonly reason: string;
  readonly reference: string;
  readonly createdAt: Date;
}

export interface AccessCommandReceipt {
  readonly commandId: string;
  readonly principal: AccessPrincipal;
  readonly targetUserId: string;
  readonly action: AccessAction;
  readonly capability: AccessCapability;
  readonly reason: string;
  readonly reference: string;
  readonly semanticFingerprint: string;
  readonly state: AccessReceiptState;
  readonly outcomeCode: Nullable<string>;
  readonly changeId: Nullable<string>;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}
import type { Nullable } from '#shared/types/absence.types';
