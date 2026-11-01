import { createParamDecorator, ExecutionContext } from '@nestjs/common';

import { Optional } from '#shared/types/absence.types';
import { readIdentitySessionCookie } from '../cookies/identity-session-cookie';
import { IdentityHttpRequest } from '../interfaces/identity-http-request';

export const IdentitySessionCookie = createParamDecorator(
  (_data: unknown, context: ExecutionContext): Optional<string> => {
    const request = context.switchToHttp().getRequest<IdentityHttpRequest>();
    return readIdentitySessionCookie(request.headers.cookie);
  },
);
