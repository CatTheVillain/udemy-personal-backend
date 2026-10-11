import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity({ name: 'identity_login_throttles' })
export class LoginThrottleEntity {
  @PrimaryGeneratedColumn('uuid')
  public id!: string;

  @Column({ name: 'key_hash', type: 'char', length: 64 })
  public keyHash!: string;

  @Column({ name: 'window_started_at', type: 'timestamptz' })
  public windowStartedAt!: Date;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  public expiresAt!: Date;

  @Column({ name: 'failure_count', type: 'integer' })
  public failureCount!: number;
}
