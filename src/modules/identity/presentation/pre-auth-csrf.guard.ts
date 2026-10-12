import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';

import {
  IdentityAuthenticationService,
  PreAuthContext,
} from '../application/identity-authentication.service';
import { PublicProblemException } from '../../../shared/http/public-problem.exception';
import { clearIdentitySessionCookie, readIdentitySessionCookie } from './identity-session-cookie';

export interface IdentityHttpRequest extends Request {
  identityPreAuth?: PreAuthContext;
}

@Injectable()
export class PreAuthCsrfGuard implements CanActivate {
  public constructor(private readonly authentication: IdentityAuthenticationService) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<IdentityHttpRequest>();
    const response = context.switchToHttp().getResponse<Response>();
    const check = await this.authentication.checkInitialPreAuth(
      readIdentitySessionCookie(request.headers.cookie),
      readCsrfHeader(request),
      request.headers.origin,
    );
    if (check.kind === 'accepted') {
      request.identityPreAuth = check.context;
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

function readCsrfHeader(request: IdentityHttpRequest): string | undefined {
  const value = request.headers['x-csrf-token'];
  if (Array.isArray(value)) return undefined;
  return value;
}
