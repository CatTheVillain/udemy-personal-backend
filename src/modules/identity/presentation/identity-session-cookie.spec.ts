import { readIdentitySessionCookie } from './identity-session-cookie';

describe('readIdentitySessionCookie', () => {
  it('distinguishes an absent cookie from malformed or ambiguous own cookies', () => {
    expect(readIdentitySessionCookie(undefined)).toBeUndefined();
    expect(readIdentitySessionCookie('other=value')).toBeUndefined();
    expect(readIdentitySessionCookie('__Host-session')).toBe('');
    expect(readIdentitySessionCookie('__Host-session=one; __Host-session=two')).toBe('');
    expect(readIdentitySessionCookie('other=value; __Host-session=opaque')).toBe('opaque');
  });
});
