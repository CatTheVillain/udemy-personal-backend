import {
  ValidationArguments,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  registerDecorator,
} from 'class-validator';

const ASCII_SPACE = 0x20;
const ASCII_MAXIMUM = 0x7f;
const MAXIMUM_EMAIL_LENGTH = 254;
const MINIMUM_PASSWORD_SCALARS = 12;
const MAXIMUM_PASSWORD_SCALARS = 128;
const MAXIMUM_PASSWORD_UTF8_BYTES = 256;

@ValidatorConstraint({ name: 'isIdentityAsciiEmail', async: false })
export class IdentityAsciiEmailConstraint implements ValidatorConstraintInterface {
  public validate(value: unknown): boolean {
    return typeof value === 'string' && isIdentityAsciiEmail(value);
  }

  public defaultMessage(_arguments: ValidationArguments): string {
    return 'email must be an ASCII value from 1 to 254 characters with a non-empty canonical value.';
  }
}

@ValidatorConstraint({ name: 'isIdentityRawPassword', async: false })
export class IdentityRawPasswordConstraint implements ValidatorConstraintInterface {
  public validate(value: unknown): boolean {
    return typeof value === 'string' && isIdentityRawPassword(value);
  }

  public defaultMessage(_arguments: ValidationArguments): string {
    return 'password must contain 12 to 128 Unicode scalar values and at most 256 UTF-8 bytes.';
  }
}

export function IsIdentityAsciiEmail(): PropertyDecorator {
  return (target: object, propertyKey: string | symbol): void => {
    registerDecorator({
      target: target.constructor,
      propertyName: propertyKey.toString(),
      validator: IdentityAsciiEmailConstraint,
    });
  };
}

export function IsIdentityRawPassword(): PropertyDecorator {
  return (target: object, propertyKey: string | symbol): void => {
    registerDecorator({
      target: target.constructor,
      propertyName: propertyKey.toString(),
      validator: IdentityRawPasswordConstraint,
    });
  };
}

export function canonicalizeIdentityEmail(value: string): string {
  const start = trimAsciiSpacesStart(value);
  const trimmed = trimAsciiSpacesEnd(start);
  let canonical = '';
  for (const character of trimmed) {
    const code = character.charCodeAt(0);
    canonical += code >= 0x41 && code <= 0x5a ? String.fromCharCode(code + 0x20) : character;
  }
  return canonical;
}

export function isIdentityAsciiEmail(value: string): boolean {
  if (value.length < 1 || value.length > MAXIMUM_EMAIL_LENGTH) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0 || code > ASCII_MAXIMUM) return false;
  }
  return canonicalizeIdentityEmail(value).length > 0;
}

export function isIdentityRawPassword(value: string): boolean {
  let scalarCount = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      scalarCount += 1;
      index += 1;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) return false;
    scalarCount += 1;
  }
  return (
    scalarCount >= MINIMUM_PASSWORD_SCALARS &&
    scalarCount <= MAXIMUM_PASSWORD_SCALARS &&
    Buffer.byteLength(value, 'utf8') <= MAXIMUM_PASSWORD_UTF8_BYTES
  );
}

function trimAsciiSpacesStart(value: string): string {
  let index = 0;
  while (index < value.length && value.charCodeAt(index) === ASCII_SPACE) index += 1;
  return value.slice(index);
}

function trimAsciiSpacesEnd(value: string): string {
  let index = value.length;
  while (index > 0 && value.charCodeAt(index - 1) === ASCII_SPACE) index -= 1;
  return value.slice(0, index);
}
