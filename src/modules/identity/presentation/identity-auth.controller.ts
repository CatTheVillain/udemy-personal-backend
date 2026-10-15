import {
  Body,
  ConflictException,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiCookieAuth,
  ApiConflictResponse,
  ApiExtraModels,
  ApiForbiddenResponse,
  ApiHeader,
  ApiHeaderOptions,
  ApiOkResponse,
  ApiOperation,
  ApiResponseNoStatusOptions,
  ApiServiceUnavailableResponse,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
  ApiCreatedResponse,
  HeadersObject,
  getSchemaPath,
} from '@nestjs/swagger';
import { Response } from 'express';

import {
  IdentityAuthenticationFailure,
  IdentityAuthenticationService,
  CsrfBootstrapOutcome,
  CsrfBootstrapRejection,
  InitialPreAuthCheck,
  PreAuthContext,
} from '../application/identity-authentication.service';
import { PasswordWorkRejection } from '../application/password-work-limiter';
import { ThrottleAdmissionRejection } from '../domain/identity.types';
import { ProblemDetailsDto } from '../../../shared/http/problem-details';
import { PublicProblemException } from '../../../shared/http/public-problem.exception';
import { AuthEmailPasswordRequestDto } from './dto/auth-email-password.request.dto';
import {
  CsrfBootstrapApiResponseDto,
  CsrfBootstrapResponseDto,
  LoginApiResponseDto,
  LoginResponseDto,
  RegistrationApiResponseDto,
  RegistrationResponseDto,
} from './dto/auth-response.dto';
import {
  clearIdentitySessionCookie,
  readIdentitySessionCookie,
  setIdentitySessionCookie,
} from './identity-session-cookie';
import { IdentityAuthTransportMapper } from './identity-auth.transport-mapper';
import { IdentityHttpRequest, PreAuthCsrfGuard } from './pre-auth-csrf.guard';

@ApiTags('identity')
@ApiExtraModels(
  CsrfBootstrapApiResponseDto,
  RegistrationApiResponseDto,
  LoginApiResponseDto,
  ProblemDetailsDto,
)
@Controller('auth')
export class IdentityAuthController {
  public constructor(private readonly authentication: IdentityAuthenticationService) {}

  @Get('csrf')
  @ApiOperation({ summary: 'Bootstrap or rotate a pre-auth CSRF token' })
  @ApiHeader(optionalRequestHeader('Cookie', 'Optional __Host-session pre-auth cookie.'))
  @ApiHeader(optionalRequestHeader('Origin', 'Optional configured browser origin.'))
  @ApiOkResponse({
    type: CsrfBootstrapApiResponseDto,
    headers: sessionCookieHeader('A new or unchanged pre-auth session cookie.'),
  })
  @ApiUnauthorizedResponse(
    problemResponse(
      'Missing, invalid, expired, or revoked pre-auth session; clears the supplied cookie.',
      'Clears the invalid pre-auth session cookie.',
    ),
  )
  @ApiForbiddenResponse(problemResponse('Disallowed origin or authenticated session'))
  @ApiTooManyRequestsResponse(
    problemResponse(
      'CSRF bootstrap source quota is exhausted (csrf_bootstrap_rate_limited).',
      undefined,
      'Retry time.',
    ),
  )
  @ApiServiceUnavailableResponse(
    problemResponse(
      'CSRF bootstrap admission is temporarily unavailable (csrf_bootstrap_unavailable, csrf_bootstrap_busy, or csrf_bootstrap_capacity_unavailable).',
      undefined,
      'Advisory retry time.',
    ),
  )
  public async bootstrapCsrf(
    @Req() request: IdentityHttpRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<CsrfBootstrapResponseDto> {
    let result: CsrfBootstrapOutcome;
    try {
      result = await this.authentication.bootstrapCsrf(
        readIdentitySessionCookie(request.headers.cookie),
        request.headers.origin,
        request.socket.remoteAddress,
      );
    } catch (error: unknown) {
      translateAuthenticationFailure(error, response);
    }
    if ('csrfToken' in result) {
      setIdentitySessionCookie(response, result.sessionToken);
      return new CsrfBootstrapResponseDto(result.csrfToken);
    }
    if (result.kind === 'clear_and_unauthorized') {
      clearIdentitySessionCookie(response);
      throw new UnauthorizedException();
    }
    if (isCsrfBootstrapRejection(result)) throwCsrfBootstrapRejection(result, response);
    throw new ForbiddenException();
  }

  @Post('register')
  @UseGuards(PreAuthCsrfGuard)
  @ApiOperation({ summary: 'Register a normal base account without authenticating it' })
  @ApiCookieAuth('preAuthSession')
  @ApiHeader(requiredRequestHeader('Origin', 'Configured browser origin.'))
  @ApiHeader({ name: 'X-CSRF-Token', required: true })
  @ApiCreatedResponse({
    type: RegistrationApiResponseDto,
    headers: sessionCookieHeader('Clears the consumed pre-auth session cookie after commit.'),
  })
  @ApiBadRequestResponse(problemResponse('Invalid request body'))
  @ApiUnauthorizedResponse(
    problemResponse(
      'Invalid pre-auth session; clears the supplied cookie.',
      'Clears the invalid cookie.',
    ),
  )
  @ApiForbiddenResponse(problemResponse('Origin or CSRF validation failed'))
  @ApiConflictResponse(problemResponse('The email is already registered'))
  @ApiTooManyRequestsResponse(
    problemResponse(
      'Registration or password-work throttle is exhausted',
      undefined,
      'Retry time.',
    ),
  )
  @ApiServiceUnavailableResponse(
    problemResponse(
      'Password-work or durable throttle capacity is temporarily unavailable',
      undefined,
      'Advisory retry time.',
    ),
  )
  public async register(
    @Body() body: AuthEmailPasswordRequestDto,
    @Req() request: IdentityHttpRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<RegistrationResponseDto> {
    const preAuth = requirePreAuth(request);
    try {
      const result = await this.authentication.register(
        preAuth,
        IdentityAuthTransportMapper.toCommand(body, request),
      );
      if (result === 'rate_limited') {
        throw new PublicProblemException(HttpStatus.TOO_MANY_REQUESTS, 'registration_rate_limited');
      }
      if (isThrottleAdmissionRejection(result)) throwThrottleAdmissionRejection(result, response);
      if (typeof result !== 'string') throwPasswordWorkRejection(result, response);
      if (result === 'duplicate') throw new ConflictException();
      clearIdentitySessionCookie(response);
      return new RegistrationResponseDto();
    } catch (error: unknown) {
      translateAuthenticationFailure(error, response);
    }
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PreAuthCsrfGuard)
  @ApiOperation({ summary: 'Authenticate with a pre-auth CSRF session' })
  @ApiCookieAuth('preAuthSession')
  @ApiHeader(requiredRequestHeader('Origin', 'Configured browser origin.'))
  @ApiHeader({ name: 'X-CSRF-Token', required: true })
  @ApiOkResponse({
    type: LoginApiResponseDto,
    headers: sessionCookieHeader('Sets a fresh authenticated session cookie after commit.'),
  })
  @ApiBadRequestResponse(problemResponse('Invalid request body'))
  @ApiUnauthorizedResponse(
    problemResponse(
      'Credentials are invalid or pre-auth is invalid. The cookie is cleared only for invalid pre-auth.',
      'Clears the cookie only when the pre-auth session is invalid; absent for credentials_invalid.',
    ),
  )
  @ApiForbiddenResponse(problemResponse('Origin or CSRF validation failed'))
  @ApiTooManyRequestsResponse(
    problemResponse('Login or password-work throttle is exhausted', undefined, 'Retry time.'),
  )
  @ApiServiceUnavailableResponse(
    problemResponse(
      'Password-work or durable throttle capacity is temporarily unavailable',
      undefined,
      'Advisory retry time.',
    ),
  )
  public async login(
    @Body() body: AuthEmailPasswordRequestDto,
    @Req() request: IdentityHttpRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<LoginResponseDto> {
    const preAuth = requirePreAuth(request);
    try {
      const result = await this.authentication.login(
        preAuth,
        IdentityAuthTransportMapper.toCommand(body, request),
      );
      if (result === 'rate_limited') {
        throw new PublicProblemException(HttpStatus.TOO_MANY_REQUESTS, 'login_rate_limited');
      }
      if (result === 'invalid_credentials') {
        throw new PublicProblemException(HttpStatus.UNAUTHORIZED, 'credentials_invalid');
      }
      if (isThrottleAdmissionRejection(result)) throwThrottleAdmissionRejection(result, response);
      if ('kind' in result) throwPasswordWorkRejection(result, response);
      setIdentitySessionCookie(response, result.sessionToken);
      return new LoginResponseDto();
    } catch (error: unknown) {
      translateAuthenticationFailure(error, response);
    }
  }
}

function requirePreAuth(request: IdentityHttpRequest): PreAuthContext {
  if (request.identityPreAuth === undefined) throw new UnauthorizedException();
  return request.identityPreAuth;
}

function translateAuthenticationFailure(error: unknown, response: Response): never {
  if (error instanceof IdentityAuthenticationFailure) {
    if (error.kind === 'csrf_invalid') {
      throw new PublicProblemException(HttpStatus.FORBIDDEN, 'CSRF_INVALID');
    }
    if (error.kind === 'unauthorized') {
      clearIdentitySessionCookie(response);
      throw new UnauthorizedException();
    }
    throw new ForbiddenException();
  }
  throw error;
}

function throwPasswordWorkRejection(result: PasswordWorkRejection, response: Response): never {
  response.setHeader('Retry-After', String(result.retryAfterSeconds));
  if (result.kind === 'rate_limited') {
    throw new PublicProblemException(HttpStatus.TOO_MANY_REQUESTS, 'password_work_rate_limited');
  }
  if (result.kind === 'busy') {
    throw new PublicProblemException(HttpStatus.SERVICE_UNAVAILABLE, 'password_work_busy');
  }
  throw new PublicProblemException(HttpStatus.SERVICE_UNAVAILABLE, 'password_work_unavailable');
}

function isThrottleAdmissionRejection(result: unknown): result is ThrottleAdmissionRejection {
  return (
    typeof result === 'object' &&
    result !== null &&
    'kind' in result &&
    ((result as { readonly kind: unknown }).kind === 'throttle_busy' ||
      (result as { readonly kind: unknown }).kind === 'throttle_capacity_unavailable')
  );
}

function throwThrottleAdmissionRejection(
  result: ThrottleAdmissionRejection,
  response: Response,
): never {
  response.setHeader('Retry-After', String(result.retryAfterSeconds));
  throw new PublicProblemException(HttpStatus.SERVICE_UNAVAILABLE, result.kind);
}

function isCsrfBootstrapRejection(
  result: InitialPreAuthCheck | CsrfBootstrapRejection,
): result is CsrfBootstrapRejection {
  return (
    result.kind === 'rate_limited' ||
    result.kind === 'unavailable' ||
    result.kind === 'busy' ||
    result.kind === 'capacity_unavailable'
  );
}

function throwCsrfBootstrapRejection(result: CsrfBootstrapRejection, response: Response): never {
  response.setHeader('Retry-After', String(result.retryAfterSeconds));
  if (result.kind === 'rate_limited') {
    throw new PublicProblemException(HttpStatus.TOO_MANY_REQUESTS, 'csrf_bootstrap_rate_limited');
  }
  if (result.kind === 'unavailable') {
    throw new PublicProblemException(HttpStatus.SERVICE_UNAVAILABLE, 'csrf_bootstrap_unavailable');
  }
  if (result.kind === 'busy') {
    throw new PublicProblemException(HttpStatus.SERVICE_UNAVAILABLE, 'csrf_bootstrap_busy');
  }
  throw new PublicProblemException(
    HttpStatus.SERVICE_UNAVAILABLE,
    'csrf_bootstrap_capacity_unavailable',
  );
}

function problemResponse(
  description: string,
  cookieDescription?: string,
  retryAfterDescription?: string,
): ApiResponseNoStatusOptions {
  const response: ApiResponseNoStatusOptions = {
    description,
    content: {
      'application/problem+json': { schema: { $ref: getSchemaPath(ProblemDetailsDto) } },
    },
  };
  if (cookieDescription !== undefined) response.headers = sessionCookieHeader(cookieDescription);
  if (retryAfterDescription !== undefined)
    response.headers = retryAfterHeader(retryAfterDescription);
  return response;
}

function retryAfterHeader(description: string): HeadersObject {
  return {
    'Retry-After': {
      description,
      schema: { type: 'string' },
    },
  };
}

function optionalRequestHeader(name: string, description: string): ApiHeaderOptions {
  return { name, required: false, description, schema: { type: 'string' } };
}

function requiredRequestHeader(name: string, description: string): ApiHeaderOptions {
  return { name, required: true, description, schema: { type: 'string' } };
}

function sessionCookieHeader(description: string): HeadersObject {
  return {
    'Set-Cookie': {
      description,
      schema: { type: 'string' },
    },
  };
}
