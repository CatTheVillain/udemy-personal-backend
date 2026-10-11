import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

import { SessionState } from '../../../domain/identity.types';

@Entity({ name: 'identity_sessions' })
export class SessionEntity {
  @PrimaryGeneratedColumn('uuid')
  public id!: string;

  @Column({ name: 'user_id', type: 'uuid', nullable: true })
  public userId!: string | null;

  @Column({ name: 'token_hash', type: 'char', length: 64 })
  public tokenHash!: string;

  @Column({ name: 'csrf_token_hash', type: 'char', length: 64 })
  public csrfTokenHash!: string;

  @Column({ type: 'varchar', length: 32 })
  public state!: SessionState;

  @Column({ name: 'created_at', type: 'timestamptz' })
  public createdAt!: Date;

  @Column({ name: 'last_seen_at', type: 'timestamptz' })
  public lastSeenAt!: Date;

  @Column({ name: 'absolute_expires_at', type: 'timestamptz' })
  public absoluteExpiresAt!: Date;

  @Column({ name: 'idle_expires_at', type: 'timestamptz' })
  public idleExpiresAt!: Date;

  @Column({ name: 'revoked_at', type: 'timestamptz', nullable: true })
  public revokedAt!: Date | null;
}
