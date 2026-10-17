import { AuthenticatedIdentity } from '../application/identity-authentication.service';
import { AuthenticatedIdentityResponseDto } from './dto/auth-response.dto';

export class IdentityAuthResponseMapper {
  public static toAuthenticatedIdentity(
    identity: AuthenticatedIdentity,
  ): AuthenticatedIdentityResponseDto {
    return new AuthenticatedIdentityResponseDto(identity.id, identity.email);
  }
}
