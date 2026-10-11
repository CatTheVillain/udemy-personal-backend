import {
  LoginThrottle,
  LoginThrottleLookup,
  RegistrationThrottle,
  RegistrationThrottleLookup,
  RevokeActiveSessionInput,
  Session,
  SessionTransitionResult,
  User,
} from '../../domain/identity.types';

export const IDENTITY_TRANSACTION_PORT = Symbol('IdentityTransactionPort');

export interface UserRepositoryPort {
  findByNormalizedEmail(normalizedEmail: string): Promise<User | null>;
  insert(user: User): Promise<void>;
}

export interface SessionRepositoryPort {
  insert(session: Session): Promise<void>;
  findById(id: string): Promise<Session | null>;
  revokeActiveSession(input: RevokeActiveSessionInput): Promise<SessionTransitionResult>;
}

export interface RegistrationThrottleRepositoryPort {
  findByKeyAndWindow(lookup: RegistrationThrottleLookup): Promise<RegistrationThrottle | null>;
  save(throttle: RegistrationThrottle): Promise<void>;
}

export interface LoginThrottleRepositoryPort {
  findByKeyAndWindow(lookup: LoginThrottleLookup): Promise<LoginThrottle | null>;
  save(throttle: LoginThrottle): Promise<void>;
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
