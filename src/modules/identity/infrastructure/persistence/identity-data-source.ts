import { DataSource } from 'typeorm';

import { IdentityDatabaseConfig } from './composition/identity-database.config';
import { createIdentityDataSource } from './composition/identity-database-options';

const identityDataSource: DataSource = createIdentityDataSource(
  IdentityDatabaseConfig.from(process.env),
);

export default identityDataSource;
