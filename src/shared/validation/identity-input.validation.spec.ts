import {
  canonicalizeIdentityEmail,
  isIdentityAsciiEmail,
  isIdentityRawPassword,
} from './identity-input.validation';

describe('identity input validation', () => {
  it('preserves the approved ASCII email canonicalization boundary', () => {
    expect(isIdentityAsciiEmail(' Example@Example.Test ')).toBe(true);
    expect(canonicalizeIdentityEmail(' Example@Example.Test ')).toBe('example@example.test');
    expect(isIdentityAsciiEmail('   ')).toBe(false);
    expect(isIdentityAsciiEmail('student@exämple.test')).toBe(false);
    expect(isIdentityAsciiEmail(`student\u0000@example.test`)).toBe(false);
  });

  it('rejects unpaired surrogates before UTF-8 conversion', () => {
    expect(isIdentityRawPassword('a'.repeat(11) + '\ud800')).toBe(false);
    expect(isIdentityRawPassword('a'.repeat(11) + '\udc00')).toBe(false);
    expect(isIdentityRawPassword(' a password 12 ')).toBe(true);
  });
});
