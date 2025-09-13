import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from '../entities/audit-log.entity';
import { User } from '../../auth/entities/user.entity';

/**
 * Audit event types for system activity tracking
 * 
 * Defines all possible audit events that can be logged.
 * Categorized by functionality for better organization and filtering.
 */
export enum AuditEventType {
  // Authentication events
  USER_LOGIN_SUCCESS = 'USER_LOGIN_SUCCESS',
  USER_LOGIN_FAILED = 'USER_LOGIN_FAILED',
  USER_LOGOUT = 'USER_LOGOUT',
  USER_REGISTER = 'USER_REGISTER',
  USER_VERIFY_EMAIL = 'USER_VERIFY_EMAIL',
  USER_RESET_PASSWORD = 'USER_RESET_PASSWORD',
  USER_CHANGE_PASSWORD = 'USER_CHANGE_PASSWORD',
  
  // Security events
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  BRUTE_FORCE_ATTEMPT = 'BRUTE_FORCE_ATTEMPT',
  
  // Data access events
  DATA_ACCESS = 'DATA_ACCESS',
  DATA_DOWNLOAD = 'DATA_DOWNLOAD',
  DATA_EXPORT = 'DATA_EXPORT',
  
  // Administrative events
  USER_ROLE_CHANGED = 'USER_ROLE_CHANGED',
  USER_STATUS_CHANGED = 'USER_STATUS_CHANGED',
  USER_DELETED = 'USER_DELETED',
  
  // Session events
  SESSION_CREATED = 'SESSION_CREATED',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  SESSION_REVOKED = 'SESSION_REVOKED',
  
  // Backup events
  BACKUP_CREATED = 'BACKUP_CREATED',
  BACKUP_RESTORED = 'BACKUP_RESTORED',
}

/**
 * Interface for audit log entries
 * 
 * Defines the structure of audit log entries with comprehensive
 * metadata for security analysis and compliance reporting.
 */
export interface AuditLogEntry {
  /** Unique identifier for the audit entry */
  id?: string;
  /** Timestamp when the event occurred */
  timestamp: Date;
  /** Type of audit event */
  event_type: AuditEventType;
  /** User ID if applicable */
  user_id?: string;
  /** User email if applicable */
  user_email?: string;
  /** Client IP address */
  ip_address?: string;
  /** User agent string */
  user_agent?: string;
  /** Session identifier */
  session_id?: string;
  /** Resource being accessed */
  resource?: string;
  /** Action performed */
  action?: string;
  /** Status of the event */
  status: 'SUCCESS' | 'FAILED' | 'WARNING';
  /** Additional event details */
  details?: Record<string, any>;
  /** Additional metadata */
  metadata?: Record<string, any>;
}

/**
 * Audit Service
 *
 * Provides comprehensive audit logging functionality for security,
 * compliance, and system monitoring purposes. All logs are persisted
 * in the database (AuditLog entity).
 *
 * Features:
 * - Comprehensive event logging (login, logout, data access, etc.)
 * - Security incident tracking
 * - User activity monitoring
 * - Administrative action logging
 * - Compliance reporting support
 *
 * Usage:
 * - Injected into services that need audit logging
 * - Provides security monitoring capabilities
 * - Supports compliance requirements
 * - Enables incident investigation
 */
@Injectable()
export class AuditService {
  /**
   * Logger for development/debug output
   */
  private readonly logger = new Logger(AuditService.name);

  /**
   * Constructor with injected repositories
   * @param auditLogRepository Repository for AuditLog entity
   * @param userRepository Repository for User entity
   */
  constructor(
    @InjectRepository(AuditLog)
    private readonly auditLogRepository: Repository<AuditLog>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  // ==========================================================================
  // CORE AUDIT LOGGING
  // ==========================================================================

  /**
   * Log an audit event (writes only to database)
   * @param event Audit event data (timestamp will be added automatically)
   */
  async log(event: Omit<AuditLogEntry, 'timestamp'>): Promise<void> {
    const auditLog = this.auditLogRepository.create({
      eventType: event.event_type,
      status: event.status,
      user: event.user_id ? { uuid: event.user_id } : undefined,
      userEmail: event.user_email,
      sessionId: event.session_id,
      ipAddress: event.ip_address,
      userAgent: event.user_agent,
      resource: event.resource,
      action: event.action,
      details: event.details || {},
      metadata: event.metadata || {},
    });
    await this.auditLogRepository.save(auditLog);
    this.logger.log(`AUDIT: ${event.event_type} - User: ${event.user_email || 'anonymous'} - Status: ${event.status}`);
  }

  /**
   * Log a successful login event
   */
  async logLoginSuccess(userId: string, userEmail: string, ipAddress?: string, userAgent?: string, sessionId?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_LOGIN_SUCCESS,
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      user_agent: userAgent,
      session_id: sessionId,
      status: 'SUCCESS',
    });
  }

  /**
   * Log failed login attempt
   * 
   * Records failed authentication attempts for security monitoring.
   * 
   * @param email - Email address used in the attempt
   * @param ipAddress - Client IP address
   * @param userAgent - User agent string
   * @param reason - Reason for failure
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logLoginFailed('user@example.com', '192.168.1.1', 'Chrome/91.0', 'Invalid password');
   */
  async logLoginFailed(email: string, ipAddress?: string, userAgent?: string, reason?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_LOGIN_FAILED,
      user_email: email,
      ip_address: ipAddress,
      user_agent: userAgent,
      status: 'FAILED',
      details: {
        reason: reason || 'Invalid credentials',
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Log user logout
   * 
   * Records user logout events for session tracking.
   * 
   * @param userId - Unique identifier of the user
   * @param userEmail - Email address of the user
   * @param sessionId - Session identifier being terminated
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logLogout('user123', 'user@example.com', 'session456');
   */
  async logLogout(userId: string, userEmail: string, sessionId?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_LOGOUT,
      user_id: userId,
      user_email: userEmail,
      session_id: sessionId,
      status: 'SUCCESS',
      details: {
        logout_method: 'user_initiated',
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Log password reset
   * 
   * Records password reset events for security monitoring.
   * 
   * @param userId - Unique identifier of the user
   * @param userEmail - Email address of the user
   * @param ipAddress - Client IP address
   * @param userAgent - User agent string
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logPasswordReset('user123', 'user@example.com', '192.168.1.1', 'Chrome/91.0');
   */
  async logPasswordReset(userId: string, userEmail: string, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_RESET_PASSWORD,
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      user_agent: userAgent,
      status: 'SUCCESS',
      details: {
        reset_method: 'email_token',
        timestamp: new Date().toISOString(),
      },
    });
  }

  // ============================================================================
  // SECURITY EVENTS
  // ============================================================================

  /**
   * Log suspicious activity
   * 
   * Records suspicious user activity for security monitoring.
   * 
   * @param userId - Unique identifier of the user
   * @param userEmail - Email address of the user
   * @param activity - Description of the suspicious activity
   * @param ipAddress - Client IP address
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logSuspiciousActivity('user123', 'user@example.com', 'Multiple failed logins', '192.168.1.1');
   */
  async logSuspiciousActivity(userId: string, userEmail: string, activity: string, ipAddress?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.SUSPICIOUS_ACTIVITY,
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      status: 'WARNING',
      details: {
        activity,
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Log brute force attempt
   * 
   * Records brute force attack attempts for security monitoring.
   * 
   * @param email - Email address targeted
   * @param ipAddress - Attacker IP address
   * @param attemptCount - Number of attempts made
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logBruteForceAttempt('user@example.com', '192.168.1.1', 10);
   */
  async logBruteForceAttempt(email: string, ipAddress: string, attemptCount: number): Promise<void> {
    await this.log({
      event_type: AuditEventType.BRUTE_FORCE_ATTEMPT,
      user_email: email,
      ip_address: ipAddress,
      status: 'WARNING',
      details: {
        attempt_count: attemptCount,
        timestamp: new Date().toISOString(),
      },
    });
  }

  // ============================================================================
  // DATA ACCESS EVENTS
  // ============================================================================

  /**
   * Log data access
   * 
   * Records data access events for compliance and monitoring.
   * 
   * @param userId - Unique identifier of the user
   * @param userEmail - Email address of the user
   * @param resource - Resource being accessed
   * @param action - Action performed (GET, POST, PUT, DELETE)
   * @param ipAddress - Client IP address
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logDataAccess('user123', 'user@example.com', '/api/users', 'GET', '192.168.1.1');
   */
  async logDataAccess(userId: string, userEmail: string, resource: string, action: string, ipAddress?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.DATA_ACCESS,
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      resource,
      action,
      status: 'SUCCESS',
      details: {
        timestamp: new Date().toISOString(),
      },
    });
  }

  // ============================================================================
  // ADMINISTRATIVE EVENTS
  // ============================================================================

  /**
   * Log administrative action
   * 
   * Records administrative actions for accountability and compliance.
   * 
   * @param adminId - Unique identifier of the admin
   * @param adminEmail - Email address of the admin
   * @param action - Administrative action performed
   * @param targetUserId - Target user ID if applicable
   * @param targetUserEmail - Target user email if applicable
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logAdminAction('admin123', 'admin@example.com', 'Change user role', 'user456', 'user@example.com');
   */
  async logAdminAction(adminId: string, adminEmail: string, action: string, targetUserId?: string, targetUserEmail?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_ROLE_CHANGED,
      user_id: adminId,
      user_email: adminEmail,
      status: 'SUCCESS',
      details: {
        action,
        target_user_id: targetUserId,
        target_user_email: targetUserEmail,
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Log user registration
   * 
   * Records new user registration events.
   * 
   * @param userId - Unique identifier of the new user
   * @param userEmail - Email address of the new user
   * @param ipAddress - Client IP address
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logUserRegistration('user123', 'newuser@example.com', '192.168.1.1');
   */
  async logUserRegistration(userId: string, userEmail: string, ipAddress?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_REGISTER,
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      status: 'SUCCESS',
      details: {
        registration_method: 'standard',
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Log user deletion
   * 
   * Records user account deletion events.
   * 
   * @param userId - Unique identifier of the deleted user
   * @param userEmail - Email address of the deleted user
   * @param ipAddress - Client IP address
   * @param userAgent - User agent string
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logUserDeletion('user123', 'user@example.com', '192.168.1.1', 'Chrome/91.0');
   */
  async logUserDeletion(userId: string, userEmail: string, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_DELETED,
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      user_agent: userAgent,
      status: 'SUCCESS',
      details: {
        deletion_method: 'admin_action',
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Log profile update
   * 
   * Records user profile update events.
   * 
   * @param userId - Unique identifier of the user
   * @param userEmail - Email address of the user
   * @param ipAddress - Client IP address
   * @param userAgent - User agent string
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logProfileUpdate('user123', 'user@example.com', '192.168.1.1', 'Chrome/91.0');
   */
  async logProfileUpdate(userId: string, userEmail: string, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_STATUS_CHANGED, // Assuming this event type for profile updates
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      user_agent: userAgent,
      status: 'SUCCESS',
      details: {
        update_method: 'user_initiated',
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Log email verification
   * 
   * Records email verification events.
   * 
   * @param userId - Unique identifier of the user
   * @param userEmail - Email address of the user
   * @param ipAddress - Client IP address
   * @param userAgent - User agent string
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logEmailVerification('user123', 'user@example.com', '192.168.1.1', 'Chrome/91.0');
   */
  async logEmailVerification(userId: string, userEmail: string, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_VERIFY_EMAIL,
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      user_agent: userAgent,
      status: 'SUCCESS',
      details: {
        verification_method: 'email_link',
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Log password change
   * 
   * Records password change events.
   * 
   * @param userId - Unique identifier of the user
   * @param userEmail - Email address of the user
   * @param ipAddress - Client IP address
   * @param userAgent - User agent string
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logPasswordChange('user123', 'user@example.com', '192.168.1.1', 'Chrome/91.0');
   */
  async logPasswordChange(userId: string, userEmail: string, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_CHANGE_PASSWORD,
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      user_agent: userAgent,
      status: 'SUCCESS',
      details: {
        change_method: 'user_initiated',
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Log failed login attempt
   * 
   * Records failed login attempts with detailed reason.
   * 
   * @param email - Email address used in the attempt
   * @param ipAddress - Client IP address
   * @param reason - Detailed reason for failure
   * @param userAgent - User agent string
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logFailedLoginAttempt('user@example.com', '192.168.1.1', 'Account locked', 'Chrome/91.0');
   */
  async logFailedLoginAttempt(email: string, ipAddress: string, reason: string, userAgent?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.USER_LOGIN_FAILED,
      user_email: email,
      ip_address: ipAddress,
      user_agent: userAgent,
      status: 'FAILED',
      details: {
        reason,
        timestamp: new Date().toISOString(),
      },
    });
  }

  // ============================================================================
  // DATA EXPORT AND BACKUP EVENTS
  // ============================================================================

  /**
   * Log data export
   * 
   * Records data export events for compliance tracking.
   * 
   * @param userId - Unique identifier of the user
   * @param userEmail - Email address of the user
   * @param resource - Resource being exported
   * @param ipAddress - Client IP address
   * @param userAgent - User agent string
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logDataExport('user123', 'user@example.com', 'user_data.csv', '192.168.1.1', 'Chrome/91.0');
   */
  async logDataExport(userId: string, userEmail: string, resource: string, ipAddress?: string, userAgent?: string): Promise<void> {
    await this.log({
      event_type: AuditEventType.DATA_EXPORT,
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      user_agent: userAgent,
      status: 'SUCCESS',
      details: {
        resource,
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Log backup creation
   * 
   * Records backup creation events for system administration.
   * 
   * @param userId - Unique identifier of the user
   * @param userEmail - Email address of the user
   * @param ipAddress - Client IP address
   * @param userAgent - User agent string
   * @param details - Additional backup details
   * @returns Promise that resolves when logging is complete
   * 
   * @example
   * await this.logBackupCreated('admin123', 'admin@example.com', '192.168.1.1', 'Chrome/91.0', { type: 'full', size: '1GB' });
   */
  async logBackupCreated(userId: string, userEmail: string, ipAddress?: string, userAgent?: string, details?: Record<string, any>): Promise<void> {
    await this.log({
      event_type: AuditEventType.BACKUP_CREATED,
      user_id: userId,
      user_email: userEmail,
      ip_address: ipAddress,
      user_agent: userAgent,
      status: 'SUCCESS',
      details: {
        ...details,
        timestamp: new Date().toISOString(),
      },
    });
  }

  // ==========================================================================
  // AUDIT LOG RETRIEVAL (from database)
  // ==========================================================================

  /**
   * Get audit logs for a specific user
   * @param userId User UUID
   * @param limit Max number of logs to return (default 100)
   */
  async getUserAuditLogs(userId: string, limit: number = 100): Promise<AuditLog[]> {
    return this.auditLogRepository.find({
      where: { user: { uuid: userId } },
      order: { timestamp: 'DESC' },
      take: limit,
    });
  }

  /**
   * Get audit logs by event type
   * @param eventType Audit event type
   * @param limit Max number of logs to return (default 100)
   */
  async getAuditLogsByType(eventType: AuditEventType, limit: number = 100): Promise<AuditLog[]> {
    return this.auditLogRepository.find({
      where: { eventType },
      order: { timestamp: 'DESC' },
      take: limit,
    });
  }

  /**
   * Get all audit logs (paginated)
   * @param limit Max number of logs to return (default 1000)
   */
  async getAllAuditLogs(limit: number = 1000): Promise<AuditLog[]> {
    return this.auditLogRepository.find({
      order: { timestamp: 'DESC' },
      take: limit,
    });
  }
} 