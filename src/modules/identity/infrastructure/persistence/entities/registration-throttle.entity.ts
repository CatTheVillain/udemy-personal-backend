import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity({ name: 'identity_registration_throttles' })
export class RegistrationThrottleEntity {
  @PrimaryGeneratedColumn('uuid')
  public id!: string;

  @Column({ name: 'key_hash', type: 'char', length: 64 })
  public keyHash!: string;

  @Column({ name: 'window_started_at', type: 'timestamptz' })
  public windowStartedAt!: Date;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  public expiresAt!: Date;

  @Column({ name: 'attempt_count', type: 'integer' })
  public attemptCount!: number;
}
