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
  ServiceUnavailableException,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ApiExtraModels, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';

import {
  AuthenticatedSessionContext,
  AuthenticatedIdentity,
  CsrfBootstrapOutcome,
  IdentityAccessFactsUnavailableFailure,
  PreAuthContext,
} from '../../../application/authentication/contracts/identity-authentication.contracts';
import { IdentityAuthenticationService } from '../../../application/authentication/services/identity-authentication.service';
import { ProblemDetailsDto } from '#shared/http/problem-details';
import { PublicProblemException } from '#shared/http/public-problem.exception';
import { CurrentAuthenticatedSession } from '../decorators/current-authenticated-session.decorator';
import { CurrentPreAuth } from '../decorators/current-pre-auth.decorator';
import { IdentitySessionCookie } from '../decorators/identity-session-cookie.decorator';
import { AuthEmailPasswordRequestDto } from '../dto/auth-email-password.request.dto';
import {
  AuthenticatedIdentityApiResponseDto,
  AuthenticatedIdentityResponseDto,
  CsrfBootstrapApiResponseDto,
  CsrfBootstrapResponseDto,
  LoginApiResponseDto,
  LoginResponseDto,
  RegistrationApiResponseDto,
  RegistrationResponseDto,
} from '../dto/auth-response.dto';
import { SkipResponseEnvelope } from '#shared/http/skip-response-envelope.decorator';
import { AuthenticatedCsrfGuard } from '../guards/authenticated-csrf.guard';
import { PreAuthCsrfGuard } from '../guards/pre-auth-csrf.guard';
import { IdentityHttpRequest } from '../interfaces/identity-http-request';
import {
  ApiAuthenticatedIdentityDocumentation,
  ApiBootstrapCsrfDocumentation,
  ApiLoginDocumentation,
  ApiLogoutDocumentation,
  ApiRegisterDocumentation,
} from '../metadata/identity-auth-openapi.metadata';
import {
  isCsrfBootstrapRejection,
  isDurableThrottleRejection,
  isThrottleAdmissionRejection,
  throwCsrfBootstrapRejection,
  throwDurableThrottleRejection,
  throwPasswordWorkRejection,
  throwThrottleAdmissionRejection,
  translateAuthenticationFailure,
} from '../mappers/identity-auth.error-mapper';
import { IdentityAuthResponseMapper } from '../mappers/identity-auth.response-mapper';
import { IdentityAuthTransportMapper } from '../mappers/identity-auth.transport-mapper';
import {
  clearIdentitySessionCookie,
  setIdentitySessionCookie,
} from '../cookies/identity-session-cookie';
import type { Nullable, Optional } from '#shared/types/absence.types';

/**
 * HTTP boundary for cookie-backed identity sessions.
 *
 * Every session-bearing response is non-cacheable; mutation endpoints rely on guard-established
 * CSRF contexts and preserve cookie clear/set effects as part of their public protocol.
 */
@ApiTags('identity')
@ApiExtraModels(
  CsrfBootstrapApiResponseDto,
  AuthenticatedIdentityApiResponseDto,
  RegistrationApiResponseDto,
  LoginApiResponseDto,
  ProblemDetailsDto,
)
@Controller('auth')
export class IdentityAuthController {
  public constructor(private readonly authentication: IdentityAuthenticationService) {}

  /** Bootstraps or rotates CSRF material and writes only the documented session-cookie effect. */
  @Get('csrf')
  @ApiBootstrapCsrfDocumentation()
  public async bootstrapCsrf(
    @IdentitySessionCookie() cookieValue: Optional<string>,
    @Req() request: IdentityHttpRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<CsrfBootstrapResponseDto> {
    let result: CsrfBootstrapOutcome;
    try {
      result = await this.authentication.bootstrapCsrf({
        cookieValue,
        origin: request.headers.origin,
        remoteAddress: request.socket.remoteAddress,
      });
    } catch (error: unknown) {
      translateAuthenticationFailure(error, response);
    }
    if ('csrfToken' in result) {
      response.setHeader('Cache-Control', 'no-store');
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

  /** Reads current identity facts without renewing the authenticated session. */
  @Get('me')
  @ApiAuthenticatedIdentityDocumentation()
  public async getAuthenticatedIdentity(
    @IdentitySessionCookie() cookieValue: Optional<string>,
    @Res({ passthrough: true }) response: Response,
  ): Promise<AuthenticatedIdentityResponseDto> {
    response.setHeader('Cache-Control', 'no-store');
    let identity: Nullable<AuthenticatedIdentity>;
    try {
      identity = await this.authentication.getAuthenticatedIdentity(cookieValue);
    } catch (error: unknown) {
      if (error instanceof IdentityAccessFactsUnavailableFailure) {
        throw new ServiceUnavailableException();
      }
      throw error;
    }
    if (identity === null) {
      clearIdentitySessionCookie(response);
      throw new UnauthorizedException();
    }
    return IdentityAuthResponseMapper.toAuthenticatedIdentity(identity);
  }

  /** Revokes the guard-validated session and clears its browser cookie. */
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  @SkipResponseEnvelope()
  @UseGuards(AuthenticatedCsrfGuard)
  @ApiLogoutDocumentation()
  public async logout(
    @CurrentAuthenticatedSession() context: AuthenticatedSessionContext,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void> {
    const result = await this.authentication.logout(context);
    if (result.kind === 'clear_and_unauthorized') {
      clearIdentitySessionCookie(response);
      throw new UnauthorizedException();
    }
    if (result.kind === 'csrf_invalid') {
      throw new PublicProblemException(HttpStatus.FORBIDDEN, 'CSRF_INVALID');
    }
    if (result.kind === 'forbidden') throw new ForbiddenException();
    clearIdentitySessionCookie(response);
  }

  /** Consumes the guard-validated pre-auth context after a successful registration transition. */
  @Post('register')
  @UseGuards(PreAuthCsrfGuard)
  @ApiRegisterDocumentation()
  public async register(
    @Body() body: AuthEmailPasswordRequestDto,
    @CurrentPreAuth() preAuth: PreAuthContext,
    @Req() request: IdentityHttpRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<RegistrationResponseDto> {
    try {
      const result = await this.authentication.register(
        preAuth,
        IdentityAuthTransportMapper.toCommand(body, request),
      );
      if (isDurableThrottleRejection(result))
        throwDurableThrottleRejection(result, response, 'registration_rate_limited');
      if (isThrottleAdmissionRejection(result)) throwThrottleAdmissionRejection(result, response);
      if (typeof result !== 'string') throwPasswordWorkRejection(result, response);
      if (result === 'duplicate') throw new ConflictException();
      clearIdentitySessionCookie(response);
      return new RegistrationResponseDto();
    } catch (error: unknown) {
      translateAuthenticationFailure(error, response);
    }
  }

  /** Replaces a consumed pre-auth context with an authenticated cookie after login succeeds. */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PreAuthCsrfGuard)
  @ApiLoginDocumentation()
  public async login(
    @Body() body: AuthEmailPasswordRequestDto,
    @CurrentPreAuth() preAuth: PreAuthContext,
    @Req() request: IdentityHttpRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<LoginResponseDto> {
    try {
      const result = await this.authentication.login(
        preAuth,
        IdentityAuthTransportMapper.toCommand(body, request),
      );
      if (isDurableThrottleRejection(result))
        throwDurableThrottleRejection(result, response, 'login_rate_limited');
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
