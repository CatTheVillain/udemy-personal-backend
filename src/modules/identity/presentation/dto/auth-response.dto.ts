import { ApiProperty } from '@nestjs/swagger';

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

export class AuthenticatedIdentityResponseDto {
  @ApiProperty()
  public readonly id: string;

  @ApiProperty()
  public readonly email: string;

  public constructor(id: string, email: string) {
    this.id = id;
    this.email = email;
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
