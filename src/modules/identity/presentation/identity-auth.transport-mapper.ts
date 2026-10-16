import { AuthEmailPasswordCommand } from '../application/identity-authentication.service';
import { AuthEmailPasswordRequestDto } from './dto/auth-email-password.request.dto';
import { IdentityHttpRequest } from './pre-auth-csrf.guard';

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
