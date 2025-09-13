import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne, JoinColumn } from 'typeorm';
import { User } from '../../auth/entities/user.entity';

/**
 * SecurityLog Entity
 *
 * Represents a single security log entry for tracking security-related events
 * such as failed logins, brute force attempts, suspicious activity, etc.
 *
 * Table: security_logs
 *
 * Features:
 * - UUID primary key
 * - Event type and severity
 * - User reference (nullable)
 * - IP address and user agent
 * - Flexible details (JSONB)
 * - Automatic timestamp
 */
@Entity('security_logs')
export class SecurityLog {
  /**
   * Unique identifier for the security log entry
   */
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * Timestamp when the event occurred
   */
  @CreateDateColumn({ name: 'timestamp' })
  timestamp: Date;

  /**
   * Type of security event (e.g., LOGIN_FAILED, BRUTE_FORCE, SUSPICIOUS_ACTIVITY)
   */
  @Column({ name: 'event_type', type: 'varchar', length: 100 })
  eventType: string;

  /**
   * Severity of the event (INFO, WARNING, ERROR, CRITICAL)
   */
  @Column({ name: 'severity', type: 'varchar', length: 20 })
  severity: string;

  /**
   * User reference (nullable for anonymous events)
   */
  @ManyToOne(() => User, { nullable: true })
  @JoinColumn({ name: 'user_uuid', referencedColumnName: 'uuid' })
  user: User;

  /**
   * User email (for quick lookup)
   */
  @Column({ name: 'user_email', type: 'varchar', length: 255, nullable: true })
  userEmail: string;

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

  /**
   * Additional metadata (flexible JSONB)
   */
  @Column({ name: 'metadata', type: 'jsonb', default: '{}' })
  metadata: Record<string, any>;
} 