import { timingSafeEqual } from 'node:crypto';

export type OperatorCredentialPurpose = 'bootstrap' | 'recovery';

const MINIMUM_CREDENTIAL_BYTES = 32;

export class AccessAdministrationOperatorUnavailableError extends Error {
  public constructor() {
    super('access_administration_operator_unavailable');
  }
}

export class IdentityAccessAdministrationCredentialsConfig {
  private constructor(
    private readonly bootstrap: Buffer,
    private readonly recovery: Buffer,
  ) {}

  public static from(
    environment: NodeJS.ProcessEnv,
  ): IdentityAccessAdministrationCredentialsConfig {
    const bootstrap = decodeCanonicalCredential(environment.IDENTITY_ACCESS_BOOTSTRAP_CREDENTIAL);
    const recovery = decodeCanonicalCredential(environment.IDENTITY_ACCESS_RECOVERY_CREDENTIAL);
    if (bootstrap === null || recovery === null || bootstrap.equals(recovery)) {
      bootstrap?.fill(0);
      recovery?.fill(0);
      throw new AccessAdministrationOperatorUnavailableError();
    }
    return new IdentityAccessAdministrationCredentialsConfig(bootstrap, recovery);
  }

  public matches(purpose: OperatorCredentialPurpose, credential: Buffer): boolean {
    const expected = purpose === 'bootstrap' ? this.bootstrap : this.recovery;
    return expected.length === credential.length && timingSafeEqual(expected, credential);
  }

  public destroy(): void {
    this.bootstrap.fill(0);
    this.recovery.fill(0);
  }
}

export function decodeCanonicalCredential(value: string | undefined): Buffer | null {
  if (value === undefined || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length < MINIMUM_CREDENTIAL_BYTES || decoded.toString('base64url') !== value) {
    decoded.fill(0);
    return null;
  }
  return decoded;
}
