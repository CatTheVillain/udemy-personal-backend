import { createParamDecorator, ExecutionContext, UnauthorizedException } from '@nestjs/common';

import { PreAuthContext } from '../../../application/authentication/contracts/identity-authentication.contracts';
import { IdentityHttpRequest } from '../interfaces/identity-http-request';

export const CurrentPreAuth = createParamDecorator(
  (_data: unknown, context: ExecutionContext): PreAuthContext => {
    const request = context.switchToHttp().getRequest<IdentityHttpRequest>();
    if (request.identityPreAuth === undefined) throw new UnauthorizedException();
    return request.identityPreAuth;
  },
);
