import { AuthenticatedIdentity } from '../../../application/authentication/contracts/identity-authentication.contracts';
import { AuthenticatedIdentityResponseDto } from '../dto/auth-response.dto';

export class IdentityAuthResponseMapper {
  public static toAuthenticatedIdentity(
    identity: AuthenticatedIdentity,
  ): AuthenticatedIdentityResponseDto {
    return new AuthenticatedIdentityResponseDto(identity.id, identity.email, identity.capabilities);
  }
}
