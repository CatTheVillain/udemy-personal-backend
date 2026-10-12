const MINIMUM_HMAC_SECRET_BYTES = 32;

export class IdentityAuthConfig {
  public readonly throttleHmacSecret: Buffer;
  public readonly corsAllowedOrigins: readonly string[];

  private constructor(throttleHmacSecret: Buffer, corsAllowedOrigins: readonly string[]) {
    this.throttleHmacSecret = throttleHmacSecret;
    this.corsAllowedOrigins = corsAllowedOrigins;
  }

  public static from(environment: NodeJS.ProcessEnv): IdentityAuthConfig {
    const value = environment.IDENTITY_THROTTLE_HMAC_SECRET;
    if (value === undefined || !/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new Error('Invalid identity authentication configuration.');
    }

    const secret = Buffer.from(value, 'base64url');
    if (secret.length < MINIMUM_HMAC_SECRET_BYTES || secret.toString('base64url') !== value) {
      throw new Error('Invalid identity authentication configuration.');
    }
    return new IdentityAuthConfig(secret, AppConfig.from(environment).corsAllowedOrigins);
  }
}
import { AppConfig } from '../../../shared/config/app-config';
