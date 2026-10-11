import { IdentityDatabaseOptions } from './identity-database-options';

export class IdentityDatabaseConfig implements IdentityDatabaseOptions {
  public readonly host: string;
  public readonly port: number;
  public readonly username: string;
  public readonly password: string;
  public readonly database: string;
  public readonly schema: string;

  private constructor(
    host: string,
    port: number,
    username: string,
    password: string,
    database: string,
    schema: string,
  ) {
    this.host = host;
    this.port = port;
    this.username = username;
    this.password = password;
    this.database = database;
    this.schema = schema;
  }

  public static from(environment: NodeJS.ProcessEnv): IdentityDatabaseConfig {
    return new IdentityDatabaseConfig(
      requiredValue(environment.DATABASE_HOST),
      parsePort(environment.DATABASE_PORT),
      requiredValue(environment.DATABASE_USERNAME),
      requiredValue(environment.DATABASE_PASSWORD),
      requiredValue(environment.DATABASE_NAME),
      requiredValue(environment.DATABASE_SCHEMA),
    );
  }
}

function requiredValue(value: string | undefined): string {
  if (value === undefined || value.trim().length === 0) {
    throw new Error('Invalid database configuration.');
  }

  return value;
}

function parsePort(value: string | undefined): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error('Invalid database configuration.');
  }

  return port;
}
