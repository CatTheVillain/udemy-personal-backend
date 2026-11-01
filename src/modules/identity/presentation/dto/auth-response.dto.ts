import { ApiProperty } from '@nestjs/swagger';

import { AccessCapability } from '../../domain/access-administration.types';

export class CsrfBootstrapResponseDto {
  @ApiProperty()
  public readonly csrfToken: string;

  public constructor(csrfToken: string) {
    this.csrfToken = csrfToken;
  }
}

export class RegistrationResponseDto {
  @ApiProperty({ example: true })
  public readonly registered: boolean;

  public constructor() {
    this.registered = true;
  }
}

export class LoginResponseDto {
  @ApiProperty({ example: true })
  public readonly authenticated: boolean;

  public constructor() {
    this.authenticated = true;
  }
}

export class AuthenticatedIdentityAccessResponseDto {
  @ApiProperty({
    enum: ['instructor', 'content_moderator', 'administrator'],
    isArray: true,
  })
  public readonly capabilities: readonly AccessCapability[];

  public constructor(capabilities: readonly AccessCapability[]) {
    this.capabilities = capabilities;
  }
}

export class AuthenticatedIdentityResponseDto {
  @ApiProperty()
  public readonly id: string;

  @ApiProperty()
  public readonly email: string;

  @ApiProperty({ type: () => AuthenticatedIdentityAccessResponseDto })
  public readonly access: AuthenticatedIdentityAccessResponseDto;

  public constructor(id: string, email: string, capabilities: readonly AccessCapability[]) {
    this.id = id;
    this.email = email;
    this.access = new AuthenticatedIdentityAccessResponseDto(capabilities);
  }
}

export class CsrfBootstrapApiResponseDto {
  @ApiProperty({ type: () => CsrfBootstrapResponseDto })
  public readonly data: CsrfBootstrapResponseDto;

  public constructor(data: CsrfBootstrapResponseDto) {
    this.data = data;
  }
}

export class RegistrationApiResponseDto {
  @ApiProperty({ type: () => RegistrationResponseDto })
  public readonly data: RegistrationResponseDto;

  public constructor(data: RegistrationResponseDto) {
    this.data = data;
  }
}

export class LoginApiResponseDto {
  @ApiProperty({ type: () => LoginResponseDto })
  public readonly data: LoginResponseDto;

  public constructor(data: LoginResponseDto) {
    this.data = data;
  }
}

export class AuthenticatedIdentityApiResponseDto {
  @ApiProperty({ type: () => AuthenticatedIdentityResponseDto })
  public readonly data: AuthenticatedIdentityResponseDto;

  public constructor(data: AuthenticatedIdentityResponseDto) {
    this.data = data;
  }
}
