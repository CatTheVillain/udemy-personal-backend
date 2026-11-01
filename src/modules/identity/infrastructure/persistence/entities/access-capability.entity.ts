import { Check, Column, CreateDateColumn, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

import { AccessCapability } from '../../../domain/access-administration.types';

@Entity({ name: 'identity_access_capabilities' })
@Check(
  'chk_identity_access_capability_value',
  "capability IN ('instructor', 'content_moderator', 'administrator')",
)
@Index('uq_identity_access_capability_active', ['userId', 'capability'], {
  unique: true,
  where: 'active',
})
export class AccessCapabilityEntity {
  @PrimaryGeneratedColumn('uuid') public id!: string;
  @Column({ name: 'user_id', type: 'uuid' }) public userId!: string;
  @Column({ type: 'varchar', length: 32 }) public capability!: AccessCapability;
  @Column({ type: 'boolean', default: true }) public active!: boolean;
  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' }) public createdAt!: Date;
}
