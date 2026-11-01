export interface ParsedScryptRecord {
  readonly salt: Buffer;
  readonly key: Buffer;
}
