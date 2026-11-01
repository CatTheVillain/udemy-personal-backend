import { randomBytes } from 'node:crypto';

import {
  decodeCanonicalCredential,
  IdentityAccessAdministrationCredentialsConfig,
} from './access-administration-config';
import { ConfigOperatorCredentialVerifier } from './operator-credential-verifier';

describe('ConfigOperatorCredentialVerifier', () => {
  it('accepts only the canonical credential for the declared purpose', async () => {
    const bootstrap = randomBytes(32).toString('base64url');
    const recovery = randomBytes(32).toString('base64url');
    const config = IdentityAccessAdministrationCredentialsConfig.from({
      IDENTITY_ACCESS_BOOTSTRAP_CREDENTIAL: bootstrap,
      IDENTITY_ACCESS_RECOVERY_CREDENTIAL: recovery,
    });
    const verifier = new ConfigOperatorCredentialVerifier(config);
    const credential = decodeCanonicalCredential(bootstrap);
    if (credential === null) throw new Error('Expected a valid test credential.');

    await expect(verifier.verify('bootstrap', credential)).resolves.toEqual({
      kind: 'bootstrap',
      binding: 'trusted-server-bootstrap',
    });
    await expect(verifier.verify('recovery', credential)).resolves.toEqual({ kind: 'rejected' });
    expect(decodeCanonicalCredential('not-base64url+')).toBeNull();
    credential.fill(0);
    verifier.onModuleDestroy();
  });
});
