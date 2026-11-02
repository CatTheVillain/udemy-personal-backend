import { Column, CreateDateColumn, Entity, PrimaryColumn, UpdateDateColumn } from 'typeorm';

import {
  AccessAction,
  AccessCapability,
  AccessPrincipalKind,
  AccessReceiptState,
} from '../../../domain/access-administration.types';
import type { Nullable } from '#shared/types/absence.types';

@Entity({ name: 'identity_access_command_receipts' })
export class AccessCommandReceiptEntity {
  @PrimaryColumn({ name: 'command_id', type: 'uuid' }) public commandId!: string;
  @Column({ name: 'principal_kind', type: 'varchar', length: 32 })
  public principalKind!: AccessPrincipalKind;
  @Column({ name: 'principal_binding', type: 'varchar', length: 64 })
  public principalBinding!: string;
  @Column({ name: 'target_user_id', type: 'uuid' }) public targetUserId!: string;
  @Column({ type: 'varchar', length: 16 }) public action!: AccessAction;
  @Column({ type: 'varchar', length: 32 }) public capability!: AccessCapability;
  @Column({ type: 'varchar', length: 512 }) public reason!: string;
  @Column({ type: 'varchar', length: 512 }) public reference!: string;
  @Column({ name: 'semantic_fingerprint', type: 'char', length: 64 })
  public semanticFingerprint!: string;
  @Column({ type: 'varchar', length: 16 }) public state!: AccessReceiptState;
  @Column({ name: 'outcome_code', type: 'varchar', length: 64, nullable: true })
  public outcomeCode!: Nullable<string>;
  @Column({ name: 'change_id', type: 'uuid', nullable: true }) public changeId!: Nullable<string>;
  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' }) public createdAt!: Date;
  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' }) public updatedAt!: Date;
}
