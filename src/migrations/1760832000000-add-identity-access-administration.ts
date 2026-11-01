import { MigrationInterface, QueryRunner } from 'typeorm';

import { identityMigrationSchema } from './identity-migration-schema';

export class AddIdentityAccessAdministration1760832000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const schema = identityMigrationSchema(queryRunner);
    await queryRunner.query(
      `CREATE TABLE ${schema}.identity_access_capabilities (
         id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
         user_id uuid NOT NULL REFERENCES ${schema}.identity_users(id),
         capability varchar(32) NOT NULL CHECK (capability IN ('instructor','content_moderator','administrator')),
         active boolean NOT NULL DEFAULT true,
         created_at timestamptz NOT NULL DEFAULT clock_timestamp()
       )`,
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX uq_identity_access_capability_active
       ON ${schema}.identity_access_capabilities (user_id, capability) WHERE active`,
    );
    await queryRunner.query(
      `CREATE TABLE ${schema}.identity_access_changes (
         id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
         command_id uuid NOT NULL UNIQUE,
         target_user_id uuid NOT NULL REFERENCES ${schema}.identity_users(id),
         principal_kind varchar(32) NOT NULL CHECK (principal_kind IN ('bootstrap','recovery','administrator')),
         principal_binding varchar(64) NOT NULL,
         action varchar(16) NOT NULL CHECK (action IN ('grant','revoke')),
         capability varchar(32) NOT NULL CHECK (capability IN ('instructor','content_moderator','administrator')),
         before_active boolean NOT NULL,
         after_active boolean NOT NULL,
         reason varchar(512) NOT NULL,
         reference varchar(512) NOT NULL,
         created_at timestamptz NOT NULL DEFAULT clock_timestamp()
       )`,
    );
    await queryRunner.query(
      `CREATE TABLE ${schema}.identity_access_command_receipts (
         command_id uuid CONSTRAINT uq_identity_access_command_receipts_command_id PRIMARY KEY,
         principal_kind varchar(32) NOT NULL CHECK (principal_kind IN ('bootstrap','recovery','administrator')),
         principal_binding varchar(64) NOT NULL,
         target_user_id uuid NOT NULL REFERENCES ${schema}.identity_users(id),
         action varchar(16) NOT NULL CHECK (action IN ('grant','revoke')),
         capability varchar(32) NOT NULL CHECK (capability IN ('instructor','content_moderator','administrator')),
         reason varchar(512) NOT NULL,
         reference varchar(512) NOT NULL,
         semantic_fingerprint char(64) NOT NULL CHECK (semantic_fingerprint ~ '^[0-9a-f]{64}$'),
         state varchar(16) NOT NULL CHECK (state IN ('pending','completed')),
         outcome_code varchar(64),
         change_id uuid REFERENCES ${schema}.identity_access_changes(id),
         created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
         updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
         CHECK ((state = 'pending' AND outcome_code IS NULL AND change_id IS NULL)
             OR (state = 'completed' AND outcome_code IS NOT NULL AND change_id IS NOT NULL))
       )`,
    );
    await queryRunner.query(
      `CREATE OR REPLACE FUNCTION ${schema}.identity_access_capability_combination_guard()
       RETURNS trigger LANGUAGE plpgsql AS $$
       BEGIN
         PERFORM 1 FROM ${schema}.identity_users WHERE id = NEW.user_id FOR UPDATE;
         IF NEW.active
           AND NEW.capability IN ('instructor','content_moderator')
           AND EXISTS (
             SELECT 1 FROM ${schema}.identity_access_capabilities
             WHERE user_id = NEW.user_id
               AND active
               AND capability IN ('instructor','content_moderator')
               AND capability <> NEW.capability
           ) THEN
           RAISE EXCEPTION 'incompatible active capability combination';
         END IF;
         RETURN NEW;
       END $$`,
    );
    await queryRunner.query(
      `CREATE TRIGGER trg_identity_access_capability_combination
       BEFORE INSERT OR UPDATE OF user_id, active, capability
       ON ${schema}.identity_access_capabilities
       FOR EACH ROW EXECUTE FUNCTION ${schema}.identity_access_capability_combination_guard()`,
    );
    await queryRunner.query(
      `CREATE OR REPLACE FUNCTION ${schema}.identity_access_change_immutable_guard()
       RETURNS trigger LANGUAGE plpgsql AS $$
       BEGIN
         RAISE EXCEPTION 'identity access changes are immutable';
       END $$`,
    );
    await queryRunner.query(
      `CREATE TRIGGER trg_identity_access_change_immutable
       BEFORE UPDATE OR DELETE ON ${schema}.identity_access_changes
       FOR EACH ROW EXECUTE FUNCTION ${schema}.identity_access_change_immutable_guard()`,
    );
    await queryRunner.query(
      `CREATE OR REPLACE FUNCTION ${schema}.identity_access_receipt_transition_guard()
       RETURNS trigger LANGUAGE plpgsql AS $$
       BEGIN
         IF TG_OP = 'DELETE' THEN
           RAISE EXCEPTION 'identity access receipts are immutable';
         END IF;
         IF OLD.state <> 'pending' OR NEW.state <> 'completed'
           OR NEW.command_id IS DISTINCT FROM OLD.command_id
           OR NEW.principal_kind IS DISTINCT FROM OLD.principal_kind
           OR NEW.principal_binding IS DISTINCT FROM OLD.principal_binding
           OR NEW.target_user_id IS DISTINCT FROM OLD.target_user_id
           OR NEW.action IS DISTINCT FROM OLD.action
           OR NEW.capability IS DISTINCT FROM OLD.capability
           OR NEW.reason IS DISTINCT FROM OLD.reason
           OR NEW.reference IS DISTINCT FROM OLD.reference
           OR NEW.semantic_fingerprint IS DISTINCT FROM OLD.semantic_fingerprint
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
           RAISE EXCEPTION 'invalid identity access receipt transition';
         END IF;
         RETURN NEW;
       END $$`,
    );
    await queryRunner.query(
      `CREATE TRIGGER trg_identity_access_receipt_transition
       BEFORE UPDATE OR DELETE ON ${schema}.identity_access_command_receipts
       FOR EACH ROW EXECUTE FUNCTION ${schema}.identity_access_receipt_transition_guard()`,
    );
  }

  public async down(): Promise<void> {
    throw new Error('Identity migrations are forward-only.');
  }
}
