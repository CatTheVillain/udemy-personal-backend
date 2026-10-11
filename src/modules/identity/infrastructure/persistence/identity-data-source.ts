import { DataSource } from 'typeorm';

import { IdentityDatabaseConfig } from '../../../../shared/database/identity-database.config';
import { createIdentityDataSource } from '../../../../shared/database/identity-database-options';

const identityDataSource: DataSource = createIdentityDataSource(
  IdentityDatabaseConfig.from(process.env),
);

export default identityDataSource;
