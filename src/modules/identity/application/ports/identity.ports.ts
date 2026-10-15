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
  RotatePreAuthCsrfInput,
  Session,
  SessionTransitionResult,
  ThrottleAdmissionRejection,
  ThrottleAdmissionResult,
  ThrottleWindowInput,
  User,
} from '../../domain/identity.types';

export const IDENTITY_TRANSACTION_PORT = Symbol('IdentityTransactionPort');

export interface UserRepositoryPort {
  findByNormalizedEmail(normalizedEmail: string): Promise<User | null>;
  insert(user: User): Promise<void>;
  insertIfAbsent(user: User): Promise<boolean>;
}

export interface SessionRepositoryPort {
  insert(session: Session): Promise<void>;
  findById(id: string): Promise<Session | null>;
  findByTokenHash(tokenHash: string): Promise<Session | null>;
  findLockedById(id: string): Promise<Session | null>;
  rotateActivePreAuthCsrf(input: RotatePreAuthCsrfInput): Promise<SessionTransitionResult>;
  consumeLockedPreAuth(input: ConsumePreAuthSessionInput): Promise<SessionTransitionResult>;
  verifyCurrentLockedPreAuth(input: VerifyCurrentPreAuthInput): Promise<SessionTransitionResult>;
  revokeActiveSession(input: RevokeActiveSessionInput): Promise<SessionTransitionResult>;
  admitBootstrapPreAuthSession(
    input: BootstrapPreAuthSessionInput,
  ): Promise<BootstrapPreAuthSessionAdmission>;
}

export interface RegistrationThrottleRepositoryPort {
  findByKeyAndWindow(lookup: RegistrationThrottleLookup): Promise<RegistrationThrottle | null>;
  save(throttle: RegistrationThrottle): Promise<void>;
  consumeAttempt(input: ThrottleWindowInput): Promise<ThrottleAdmissionResult>;
}

export interface LoginThrottleRepositoryPort {
  findByKeyAndWindow(lookup: LoginThrottleLookup): Promise<LoginThrottle | null>;
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
}

export interface IdentityTransactionWork<Result> {
  execute(scope: IdentityTransactionScope): Promise<Result>;
}

export interface IdentityTransactionPort {
  run<Result>(work: IdentityTransactionWork<Result>): Promise<Result>;
}
