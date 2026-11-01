import {
  LoginThrottle,
  LoginThrottleLookup,
  BootstrapPreAuthSessionAdmission,
  BootstrapPreAuthSessionInput,
  ConsumePreAuthSessionInput,
  VerifyCurrentPreAuthInput,
  RegistrationThrottle,
  RegistrationThrottleLookup,
  RevokeActiveSessionInput,
  RevokeAuthenticatedSessionInput,
  RotateAuthenticatedCsrfInput,
  RotatePreAuthCsrfInput,
  Session,
  SessionTransitionResult,
  ThrottleAdmissionRejection,
  ThrottleAdmissionResult,
  ThrottleWindowInput,
  User,
} from '../../domain/identity.types';
import {
  AccessAction,
  AccessCapability,
  AccessCapabilityProjectionRead,
  AccessCapabilityRecord,
  AccessChange,
  AccessCommandReceipt,
  AccessPrincipal,
  AccessTransition,
} from '../../domain/access-administration.types';
import type { Nullable } from '#shared/types/absence.types';

export const IDENTITY_TRANSACTION_PORT = Symbol('IdentityTransactionPort');

export interface UserRepositoryPort {
  findByNormalizedEmail(normalizedEmail: string): Promise<Nullable<User>>;
  findById(id: string): Promise<Nullable<User>>;
  findLockedByIds(ids: readonly string[]): Promise<readonly User[]>;
  insert(user: User): Promise<void>;
  insertIfAbsent(user: User): Promise<boolean>;
}

export interface SessionRepositoryPort {
  insert(session: Session): Promise<void>;
  findById(id: string): Promise<Nullable<Session>>;
  findByTokenHash(tokenHash: string): Promise<Nullable<Session>>;
  findLockedById(id: string): Promise<Nullable<Session>>;
  findLockedAuthenticatedByTokenHash(tokenHash: string): Promise<Nullable<Session>>;
  findCurrentLockedAuthenticated(id: string, tokenHash: string): Promise<Nullable<Session>>;
  findAccessAdministrationCurrentLockedAuthenticated(
    id: string,
    tokenHash: string,
  ): Promise<Nullable<Session>>;
  rotateActivePreAuthCsrf(input: RotatePreAuthCsrfInput): Promise<SessionTransitionResult>;
  rotateCurrentAuthenticatedCsrf(
    input: RotateAuthenticatedCsrfInput,
  ): Promise<SessionTransitionResult>;
  consumeLockedPreAuth(input: ConsumePreAuthSessionInput): Promise<SessionTransitionResult>;
  verifyCurrentLockedPreAuth(input: VerifyCurrentPreAuthInput): Promise<SessionTransitionResult>;
  revokeActiveSession(input: RevokeActiveSessionInput): Promise<SessionTransitionResult>;
  revokeCurrentAuthenticatedSession(
    input: RevokeAuthenticatedSessionInput,
  ): Promise<SessionTransitionResult>;
  admitBootstrapPreAuthSession(
    input: BootstrapPreAuthSessionInput,
  ): Promise<BootstrapPreAuthSessionAdmission>;
}

export type AccessMembershipLockResult =
  { readonly kind: 'acquired' } | { readonly kind: 'busy'; readonly retryAfterSeconds: 1 };

export interface AccessAdministrationLockRepositoryPort {
  tryAcquireAdministratorMembershipLock(): Promise<AccessMembershipLockResult>;
}

export interface NewAccessChange {
  readonly commandId: string;
  readonly targetUserId: string;
  readonly principal: AccessPrincipal;
  readonly action: AccessAction;
  readonly capability: AccessCapability;
  readonly beforeActive: boolean;
  readonly afterActive: boolean;
  readonly reason: string;
  readonly reference: string;
}

export interface NewAccessCommandReceipt {
  readonly commandId: string;
  readonly principal: AccessPrincipal;
  readonly targetUserId: string;
  readonly action: AccessAction;
  readonly capability: AccessCapability;
  readonly reason: string;
  readonly reference: string;
  readonly semanticFingerprint: string;
}

export interface AccessReceiptCompletion {
  readonly outcomeCode: string;
  readonly changeId: string;
}

export type AccessReceiptPendingInsertResult =
  { readonly kind: 'inserted' } | { readonly kind: 'command_id_collision' };

export interface AccessCapabilityRepositoryPort {
  findActiveProjectionForUser(userId: string): Promise<AccessCapabilityProjectionRead>;
  findActiveLocked(
    userId: string,
    capability: AccessCapability,
  ): Promise<Nullable<AccessCapabilityRecord>>;
  hasActiveLocked(userId: string, capability: AccessCapability): Promise<boolean>;
  lockActiveAdministratorsAndCount(): Promise<number>;
  applyTransition(transition: AccessTransition): Promise<Nullable<AccessCapabilityRecord>>;
}

export interface AccessChangeRepositoryPort {
  insert(change: NewAccessChange): Promise<AccessChange>;
}

export interface AccessReceiptRepositoryPort {
  findByCommandId(commandId: string): Promise<Nullable<AccessCommandReceipt>>;
  insertPending(receipt: NewAccessCommandReceipt): Promise<AccessReceiptPendingInsertResult>;
  complete(commandId: string, completion: AccessReceiptCompletion): Promise<void>;
}

export interface RegistrationThrottleRepositoryPort {
  findByKeyAndWindow(lookup: RegistrationThrottleLookup): Promise<Nullable<RegistrationThrottle>>;
  save(throttle: RegistrationThrottle): Promise<void>;
  consumeAttempt(input: ThrottleWindowInput): Promise<ThrottleAdmissionResult>;
}

export interface LoginThrottleRepositoryPort {
  findByKeyAndWindow(lookup: LoginThrottleLookup): Promise<Nullable<LoginThrottle>>;
  save(throttle: LoginThrottle): Promise<void>;
  acquireForLogin(input: ThrottleWindowInput): Promise<LoginThrottle | ThrottleAdmissionRejection>;
  consumeFailure(keyHash: string, now: Date): Promise<ThrottleAdmissionResult>;
  resetFailures(keyHash: string, now: Date): Promise<void>;
}

export interface IdentityTransactionScope {
  readonly users: UserRepositoryPort;
  readonly sessions: SessionRepositoryPort;
  readonly registrationThrottles: RegistrationThrottleRepositoryPort;
  readonly loginThrottles: LoginThrottleRepositoryPort;
  readonly accessAdministrationLocks: AccessAdministrationLockRepositoryPort;
  readonly accessCapabilities: AccessCapabilityRepositoryPort;
  readonly accessChanges: AccessChangeRepositoryPort;
  readonly accessReceipts: AccessReceiptRepositoryPort;
}

export interface IdentityTransactionWork<Result> {
  execute(scope: IdentityTransactionScope): Promise<Result>;
}

export interface IdentityTransactionPort {
  run<Result>(work: IdentityTransactionWork<Result>): Promise<Result>;
}
