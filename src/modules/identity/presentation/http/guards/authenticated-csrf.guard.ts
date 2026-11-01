import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Response } from 'express';

import { IdentityAuthenticationService } from '../../../application/authentication/services/identity-authentication.service';
import { PublicProblemException } from '#shared/http/public-problem.exception';
import {
  clearIdentitySessionCookie,
  readIdentitySessionCookie,
} from '../cookies/identity-session-cookie';
import { readCsrfHeader } from '../helpers/identity-http-request.helpers';
import { AuthenticatedIdentityHttpRequest } from '../interfaces/identity-http-request';

@Injectable()
export class AuthenticatedCsrfGuard implements CanActivate {
  public constructor(private readonly authentication: IdentityAuthenticationService) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedIdentityHttpRequest>();
    const response = context.switchToHttp().getResponse<Response>();
    const check = await this.authentication.checkAuthenticatedCsrf({
      cookieValue: readIdentitySessionCookie(request.headers.cookie),
      csrfToken: readCsrfHeader(request),
      origin: request.headers.origin,
    });
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
