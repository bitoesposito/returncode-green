import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne, JoinColumn } from 'typeorm';
import { User } from '../../auth/entities/user.entity';

/**
 * SessionLog Entity
 *
 * Represents a single session log entry for tracking user session lifecycle events
 * such as creation, expiration, revocation, and device info.
 *
 * Table: session_logs
 *
 * Features:
 * - UUID primary key
 * - Event type (CREATED, EXPIRED, REVOKED)
 * - User reference
 * - Session token (hashed)
 * - Device info, IP, user agent
 * - Automatic timestamp
 */
@Entity('session_logs')
export class SessionLog {
  /**
   * Unique identifier for the session log entry
   */
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * Timestamp when the event occurred
   */
  @CreateDateColumn({ name: 'timestamp' })
  timestamp: Date;

  /**
   * Type of session event (CREATED, EXPIRED, REVOKED)
   */
  @Column({ name: 'event_type', type: 'varchar', length: 50 })
  eventType: string;

  /**
   * User reference
   */
  @ManyToOne(() => User, { nullable: true })
  @JoinColumn({ name: 'user_uuid', referencedColumnName: 'uuid' })
  user: User;

  /**
   * Session token (hashed for security)
   */
  @Column({ name: 'session_token_hash', type: 'varchar', length: 255 })
  sessionTokenHash: string;

  /**
   * Refresh token (hashed for security)
   */
  @Column({ name: 'refresh_token_hash', type: 'varchar', length: 255, nullable: true })
  refreshTokenHash: string;

  /**
   * Device information (browser, OS, etc.)
   */
  @Column({ name: 'device_info', type: 'varchar', length: 255, nullable: true })
  deviceInfo: string;

  /**
   * Client IP address
   */
  @Column({ name: 'ip_address', type: 'varchar', length: 64, nullable: true })
  ipAddress: string;

  /**
   * User agent string
   */
  @Column({ name: 'user_agent', type: 'text', nullable: true })
  userAgent: string;

  /**
   * Additional details (flexible JSONB)
   */
  @Column({ name: 'details', type: 'jsonb', default: '{}' })
  details: Record<string, any>;
} 