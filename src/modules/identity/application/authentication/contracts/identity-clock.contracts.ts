/** Clock boundary used by identity session lifetime calculations. */
export interface IdentityClock {
  now(): Date;
}

export const IDENTITY_CLOCK = Symbol('IdentityClock');
