import { Request } from 'express';

import {
  AuthenticatedSessionContext,
  PreAuthContext,
} from '../../../application/authentication/contracts/identity-authentication.contracts';

export interface IdentityHttpRequest extends Request {
  identityPreAuth?: PreAuthContext;
}

/** Request state established only after the authenticated CSRF guard succeeds. */
export interface AuthenticatedIdentityHttpRequest extends IdentityHttpRequest {
  identityAuthenticated?: AuthenticatedSessionContext;
}
