import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn } from 'typeorm';

import {
  AccessAction,
  AccessCapability,
  AccessPrincipalKind,
} from '../../../domain/access-administration.types';

@Entity({ name: 'identity_access_changes' })
export class AccessChangeEntity {
  @PrimaryGeneratedColumn('uuid') public id!: string;
  @Column({ name: 'command_id', type: 'uuid' }) public commandId!: string;
  @Column({ name: 'target_user_id', type: 'uuid' }) public targetUserId!: string;
  @Column({ name: 'principal_kind', type: 'varchar', length: 32 })
  public principalKind!: AccessPrincipalKind;
  @Column({ name: 'principal_binding', type: 'varchar', length: 64 })
  public principalBinding!: string;
  @Column({ type: 'varchar', length: 16 }) public action!: AccessAction;
  @Column({ type: 'varchar', length: 32 }) public capability!: AccessCapability;
  @Column({ name: 'before_active', type: 'boolean' }) public beforeActive!: boolean;
  @Column({ name: 'after_active', type: 'boolean' }) public afterActive!: boolean;
  @Column({ type: 'varchar', length: 512 }) public reason!: string;
  @Column({ type: 'varchar', length: 512 }) public reference!: string;
  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' }) public createdAt!: Date;
}
