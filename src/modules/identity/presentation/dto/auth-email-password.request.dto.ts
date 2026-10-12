import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

import {
  IsIdentityAsciiEmail,
  IsIdentityRawPassword,
} from '../../../../shared/validation/identity-input.validation';

export class AuthEmailPasswordRequestDto {
  @ApiProperty({ example: 'student@example.test', minLength: 1, maxLength: 254 })
  @IsString()
  @IsIdentityAsciiEmail()
  public readonly email!: string;

  @ApiProperty({ example: 'not-a-real-password' })
  @IsString()
  @IsIdentityRawPassword()
  public readonly password!: string;
}
