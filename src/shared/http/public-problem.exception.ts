import { HttpException, HttpStatus } from '@nestjs/common';

export type PublicProblemCode =
  'CSRF_INVALID' | 'credentials_invalid' | 'registration_rate_limited' | 'login_rate_limited';

export class PublicProblemException extends HttpException {
  public constructor(
    status: HttpStatus,
    public readonly code: PublicProblemCode,
  ) {
    super(code, status);
  }
}
