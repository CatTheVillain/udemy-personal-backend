import { createParamDecorator, ExecutionContext, UnauthorizedException } from '@nestjs/common';

import { AuthenticatedSessionContext } from '../../../application/authentication/contracts/identity-authentication.contracts';
import { AuthenticatedIdentityHttpRequest } from '../interfaces/identity-http-request';

export const CurrentAuthenticatedSession = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AuthenticatedSessionContext => {
    const request = context.switchToHttp().getRequest<AuthenticatedIdentityHttpRequest>();
    if (request.identityAuthenticated === undefined) throw new UnauthorizedException();
    return request.identityAuthenticated;
  },
);
