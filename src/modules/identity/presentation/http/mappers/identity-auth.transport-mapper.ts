import { AuthEmailPasswordCommand } from '../../../application/authentication/contracts/identity-authentication.contracts';
import { AuthEmailPasswordRequestDto } from '../dto/auth-email-password.request.dto';
import { IdentityHttpRequest } from '../interfaces/identity-http-request';

export class IdentityAuthTransportMapper {
  public static toCommand(
    source: AuthEmailPasswordRequestDto,
    request: IdentityHttpRequest,
  ): AuthEmailPasswordCommand {
    return {
      email: source.email,
      password: source.password,
      remoteAddress: request.socket.remoteAddress,
    };
  }
}
