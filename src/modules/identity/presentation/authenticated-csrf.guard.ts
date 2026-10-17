import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Response } from 'express';

import {
  AuthenticatedSessionContext,
  IdentityAuthenticationService,
} from '../application/identity-authentication.service';
import { PublicProblemException } from '../../../shared/http/public-problem.exception';
import { clearIdentitySessionCookie, readIdentitySessionCookie } from './identity-session-cookie';
import { IdentityHttpRequest } from './pre-auth-csrf.guard';

export interface AuthenticatedIdentityHttpRequest extends IdentityHttpRequest {
  identityAuthenticated?: AuthenticatedSessionContext;
}

@Injectable()
export class AuthenticatedCsrfGuard implements CanActivate {
  public constructor(private readonly authentication: IdentityAuthenticationService) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedIdentityHttpRequest>();
    const response = context.switchToHttp().getResponse<Response>();
    const check = await this.authentication.checkAuthenticatedCsrf(
      readIdentitySessionCookie(request.headers.cookie),
      readCsrfHeader(request),
      request.headers.origin,
    );
    if (check.kind === 'accepted') {
      request.identityAuthenticated = check.context;
      return true;
    }
    if (check.kind === 'clear_and_unauthorized') {
      clearIdentitySessionCookie(response);
      throw new UnauthorizedException();
    }
    if (check.kind === 'csrf_invalid') {
      throw new PublicProblemException(403, 'CSRF_INVALID');
    }
    throw new ForbiddenException();
  }
}

function readCsrfHeader(request: AuthenticatedIdentityHttpRequest): string | undefined {
  const value = request.headers['x-csrf-token'];
  if (Array.isArray(value)) return undefined;
  return value;
}
