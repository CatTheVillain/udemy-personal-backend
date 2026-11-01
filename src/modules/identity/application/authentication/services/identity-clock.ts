import { IdentityClock } from '../contracts/identity-clock.contracts';

export class SystemIdentityClock implements IdentityClock {
  public now(): Date {
    return new Date();
  }
}
