import { QueryRunner } from 'typeorm';

const POSTGRES_IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

export function identityMigrationSchema(queryRunner: QueryRunner): string {
  const options = queryRunner.connection.options;
  if (options.type !== 'postgres' || options.schema === undefined) {
    throw new Error('Identity migrations require a PostgreSQL schema.');
  }
  if (!POSTGRES_IDENTIFIER.test(options.schema)) {
    throw new Error('Identity migrations require a safe PostgreSQL schema.');
  }
  return options.schema;
}

export function qualifiedIdentityTable(schema: string, tableName: string): string {
  return `${schema}.${tableName}`;
}
