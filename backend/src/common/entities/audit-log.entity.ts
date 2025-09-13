import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne, JoinColumn } from 'typeorm';
import { User } from '../../auth/entities/user.entity';

/**
 * AuditLog Entity
 *
 * Represents a single audit log entry for security, compliance, and monitoring.
 * All critical system and user actions are recorded here for traceability.
 *
 * Table: audit_logs
 *
 * Features:
 * - UUID primary key
 * - Event type and status
 * - User and session references
 * - IP address and user agent
 * - Flexible details (JSONB)
 * - Automatic timestamp
 */
@Entity('audit_logs')
export class AuditLog {
  /**
   * Unique identifier for the audit log entry
   */
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * Timestamp when the event occurred
   */
  @CreateDateColumn({ name: 'timestamp' })
  timestamp: Date;

  /**
   * Type of audit event (e.g., LOGIN_SUCCESS, DATA_ACCESS)
   */
  @Column({ name: 'event_type', type: 'varchar', length: 100 })
  eventType: string;

  /**
   * Status of the event (SUCCESS, FAILED, WARNING)
   */
  @Column({ name: 'status', type: 'varchar', length: 20 })
  status: string;

  /**
   * User reference (nullable for system events)
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
   * Session identifier (if available)
   */
  @Column({ name: 'session_id', type: 'varchar', length: 255, nullable: true })
  sessionId: string;

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
   * Resource or endpoint accessed
   */
  @Column({ name: 'resource', type: 'varchar', length: 255, nullable: true })
  resource: string;

  /**
   * Action performed (e.g., GET, POST, DELETE)
   */
  @Column({ name: 'action', type: 'varchar', length: 50, nullable: true })
  action: string;

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