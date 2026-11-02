import { AccessCapability } from '../../../domain/access-administration.types';
import {
  DurableThrottleRejection,
  ThrottleAdmissionRejection,
} from '../../../domain/identity.types';
import { Optional } from '#shared/types/absence.types';
import {
  CsrfBootstrapRateLimited,
  CsrfBootstrapUnavailable,
} from '../helpers/csrf-bootstrap-limiter';
import { PasswordWorkRejection } from '../../credentials/contracts/password-work.contracts';

export interface AuthEmailPasswordCommand {
  readonly email: string;
  readonly password: string;
  readonly remoteAddress: Optional<string>;
}

export interface AuthenticatedCsrfCheckInput {
  readonly cookieValue: Optional<string>;
  readonly csrfToken: Optional<string>;
  readonly origin: Optional<string>;
}

export interface CsrfBootstrapInput {
  readonly cookieValue: Optional<string>;
  readonly origin: Optional<string>;
  readonly remoteAddress: Optional<string>;
}

export interface PreAuthCsrfCheckInput {
  readonly cookieValue: Optional<string>;
  readonly csrfToken: Optional<string>;
  readonly origin: Optional<string>;
}

export interface PreAuthContext {
  readonly sessionId: string;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
}

export interface AuthenticatedSessionContext {
  readonly sessionId: string;
  readonly tokenHash: string;
  readonly csrfTokenHash: string;
}

export interface AuthenticatedIdentity {
  readonly id: string;
  readonly email: string;
  readonly capabilities: readonly AccessCapability[];
}

export interface CsrfBootstrapResult {
  readonly csrfToken: string;
  readonly sessionToken: string;
}

export type CsrfBootstrapRejection =
  | CsrfBootstrapRateLimited
  | CsrfBootstrapUnavailable
  | { readonly kind: 'busy'; readonly retryAfterSeconds: 1 }
  | { readonly kind: 'capacity_unavailable'; readonly retryAfterSeconds: 60 };

export type CsrfBootstrapOutcome =
  CsrfBootstrapResult | InitialPreAuthCheck | AuthenticatedCsrfCheck | CsrfBootstrapRejection;

export type AuthenticatedCsrfCheck =
  | {
      readonly kind: 'authenticated_csrf';
      readonly csrfToken: string;
      readonly sessionToken: string;
    }
  | { readonly kind: 'clear_and_unauthorized' };

export type AuthenticatedSessionCheck =
  | { readonly kind: 'accepted'; readonly context: AuthenticatedSessionContext }
  | { readonly kind: 'clear_and_unauthorized' }
  | { readonly kind: 'forbidden' }
  | { readonly kind: 'csrf_invalid' };

export interface AuthenticatedSessionResult {
  readonly sessionToken: string;
}

export type RegistrationResult =
  | 'registered'
  | 'duplicate'
  | DurableThrottleRejection
  | PasswordWorkRejection
  | ThrottleAdmissionRejection;

export type LoginResult =
  | 'invalid_credentials'
  | DurableThrottleRejection
  | PasswordWorkRejection
  | ThrottleAdmissionRejection;

export type InitialPreAuthCheck =
  | { readonly kind: 'accepted'; readonly context: PreAuthContext }
  | { readonly kind: 'clear_and_unauthorized' }
  | { readonly kind: 'forbidden' }
  | { readonly kind: 'csrf_invalid' };

export type IdentityAuthenticationFailureKind = 'csrf_invalid' | 'forbidden' | 'unauthorized';

/** Expected authentication-state failure translated by the HTTP boundary. */
export class IdentityAuthenticationFailure extends Error {
  public constructor(public readonly kind: IdentityAuthenticationFailureKind) {
    super(kind);
  }
}

/** Signals that current access facts could not be read safely. */
export class IdentityAccessFactsUnavailableFailure extends Error {}
