import { MigrationInterface, QueryRunner } from 'typeorm';

import { identityMigrationSchema, qualifiedIdentityTable } from './identity-migration-schema';

export class AddIdentityPersistenceInvariants1760194800001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const schema = identityMigrationSchema(queryRunner);
    const users = qualifiedIdentityTable(schema, 'identity_users');
    const sessions = qualifiedIdentityTable(schema, 'identity_sessions');
    const registrationThrottles = qualifiedIdentityTable(schema, 'identity_registration_throttles');
    const loginThrottles = qualifiedIdentityTable(schema, 'identity_login_throttles');

    await queryRunner.query(
      `ALTER TABLE ${users} ADD CONSTRAINT uq_identity_user_normalized_email UNIQUE (normalized_email)`,
    );
    await queryRunner.query(
      `ALTER TABLE ${users} ADD CONSTRAINT chk_identity_user_normalized_email CHECK (normalized_email = lower(btrim(normalized_email)) AND char_length(normalized_email) BETWEEN 1 AND 254)`,
    );
    await queryRunner.query(
      `ALTER TABLE ${sessions} ADD CONSTRAINT uq_identity_session_token_hash UNIQUE (token_hash)`,
    );
    await queryRunner.query(
      `ALTER TABLE ${sessions} ADD CONSTRAINT chk_identity_session_lifecycle CHECK ((state = 'pre_auth' AND user_id IS NULL AND revoked_at IS NULL) OR (state = 'authenticated' AND user_id IS NOT NULL AND revoked_at IS NULL) OR (state = 'revoked' AND revoked_at IS NOT NULL))`,
    );
    await queryRunner.query(
      `ALTER TABLE ${sessions} ADD CONSTRAINT chk_identity_session_expiry CHECK (created_at <= last_seen_at AND last_seen_at < idle_expires_at AND idle_expires_at <= absolute_expires_at)`,
    );
    await queryRunner.query(
      `ALTER TABLE ${sessions} ADD CONSTRAINT chk_identity_session_hashes CHECK (token_hash ~ '^[0-9a-f]{64}$' AND csrf_token_hash ~ '^[0-9a-f]{64}$')`,
    );
    await queryRunner.query(
      `ALTER TABLE ${registrationThrottles} ADD CONSTRAINT uq_identity_registration_throttle_key_window UNIQUE (key_hash, window_started_at)`,
    );
    await queryRunner.query(
      `ALTER TABLE ${registrationThrottles} ADD CONSTRAINT chk_identity_registration_throttle_window CHECK (key_hash ~ '^[0-9a-f]{64}$' AND attempt_count >= 0 AND expires_at > window_started_at)`,
    );
    await queryRunner.query(
      `ALTER TABLE ${loginThrottles} ADD CONSTRAINT uq_identity_login_throttle_key_window UNIQUE (key_hash, window_started_at)`,
    );
    await queryRunner.query(
      `ALTER TABLE ${loginThrottles} ADD CONSTRAINT chk_identity_login_throttle_window CHECK (key_hash ~ '^[0-9a-f]{64}$' AND failure_count >= 0 AND expires_at > window_started_at)`,
    );
  }

  public async down(): Promise<void> {
    throw new Error('Identity migrations are forward-only.');
  }
}
