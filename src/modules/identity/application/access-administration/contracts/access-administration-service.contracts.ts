import { AccessPrincipal } from '../../../domain/access-administration.types';

import { AccessAdministrationOutcome } from './access-administration.contracts';

export interface AccessAuthorizationSuccess {
  readonly principal: AccessPrincipal;
}

export interface AccessAuthorizationFailure {
  readonly outcome: AccessAdministrationOutcome;
}

export type AccessAuthorizationResult = AccessAuthorizationSuccess | AccessAuthorizationFailure;

export interface AccessReceiptAbsent {
  readonly kind: 'absent';
  readonly outcome: AccessAdministrationOutcome;
}

export interface AccessReceiptPresent {
  readonly kind: 'present';
  readonly outcome: AccessAdministrationOutcome;
}

export type AccessReceiptLookupResult = AccessReceiptAbsent | AccessReceiptPresent;
