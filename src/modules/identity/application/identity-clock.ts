export const IDENTITY_CLOCK = Symbol('IdentityClock');

export interface IdentityClock {
  now(): Date;
}

export class SystemIdentityClock implements IdentityClock {
  public now(): Date {
    return new Date();
  }
}
