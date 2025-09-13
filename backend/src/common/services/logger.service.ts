import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SecurityLog } from '../entities/security-log.entity';
import { User } from '../../auth/entities/user.entity';

/**
 * Log levels for application logging
 *
 * Defines the available log levels for structured logging.
 * Each level represents a different severity of log message.
 */
export enum LogLevel {
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
  DEBUG = 'DEBUG',
}

/**
 * Interface for structured log entries
 *
 * Defines the structure of log entries written to the database.
 * Provides consistent formatting for all log messages.
 */
export interface LogEntry {
  timestamp?: string;
  level: LogLevel;
  message: string;
  context?: string;
  metadata?: Record<string, any>;
}

/**
 * Logger Service
 *
 * Provides centralized logging functionality for the application.
 * Implements database-based logging for security and system events.
 *
 * Features:
 * - Multiple log levels (INFO, WARN, ERROR, DEBUG)
 * - Structured JSON logging
 * - Database-based log persistence (SecurityLog entity)
 * - Context and metadata support
 *
 * Usage:
 * - Injected into other services for logging
 * - Provides consistent logging across the application
 * - Supports structured logging for better analysis
 */
@Injectable()
export class LoggerService {
  /**
   * Logger for development/debug output
   */
  private readonly logger = new Logger('AppLogger');

  /**
   * Constructor with injected repositories
   * @param securityLogRepository Repository for SecurityLog entity
   * @param userRepository Repository for User entity
   */
  constructor(
    @InjectRepository(SecurityLog)
    private readonly securityLogRepository: Repository<SecurityLog>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  // ==========================================================================
  // PRIVATE UTILITY METHODS
  // ==========================================================================

  /**
   * Write a log entry to the database (SecurityLog)
   * @param entry Log entry data
   * @param userId Optional user UUID
   * @param userEmail Optional user email
   * @param ipAddress Optional client IP address
   * @param userAgent Optional user agent string
   */
  private async writeToDatabase(entry: LogEntry, userId?: string, userEmail?: string, ipAddress?: string, userAgent?: string) {
    const securityLog = this.securityLogRepository.create({
      eventType: entry.context || entry.level,
      severity: entry.level,
      user: userId ? { uuid: userId } : undefined,
      userEmail: userEmail,
      ipAddress: ipAddress,
      userAgent: userAgent,
      details: entry.metadata || {},
      metadata: {},
    });
    await this.securityLogRepository.save(securityLog);
  }

  // ==========================================================================
  // PUBLIC LOGGING METHODS
  // ==========================================================================

  /**
   * Log informational message
   * @param message Informational message to log
   * @param context Optional context for categorizing the log
   * @param metadata Optional additional data for the log entry
   * @param userId Optional user UUID
   * @param userEmail Optional user email
   * @param ipAddress Optional client IP address
   * @param userAgent Optional user agent string
   */
  info(message: string, context?: string, metadata?: Record<string, any>, userId?: string, userEmail?: string, ipAddress?: string, userAgent?: string): void {
    const entry: LogEntry = { level: LogLevel.INFO, message, context, metadata };
    this.logger.log(JSON.stringify(entry));
    this.writeToDatabase(entry, userId, userEmail, ipAddress, userAgent);
  }

  /**
   * Log warning message
   * @param message Warning message to log
   * @param context Optional context for categorizing the log
   * @param metadata Optional additional data for the log entry
   * @param userId Optional user UUID
   * @param userEmail Optional user email
   * @param ipAddress Optional client IP address
   * @param userAgent Optional user agent string
   */
  warn(message: string, context?: string, metadata?: Record<string, any>, userId?: string, userEmail?: string, ipAddress?: string, userAgent?: string): void {
    const entry: LogEntry = { level: LogLevel.WARN, message, context, metadata };
    this.logger.warn(JSON.stringify(entry));
    this.writeToDatabase(entry, userId, userEmail, ipAddress, userAgent);
  }

  /**
   * Log error message
   * @param message Error message to log
   * @param context Optional context for categorizing the log
   * @param metadata Optional additional data for the log entry
   * @param userId Optional user UUID
   * @param userEmail Optional user email
   * @param ipAddress Optional client IP address
   * @param userAgent Optional user agent string
   */
  error(message: string, context?: string, metadata?: Record<string, any>, userId?: string, userEmail?: string, ipAddress?: string, userAgent?: string): void {
    const entry: LogEntry = { level: LogLevel.ERROR, message, context, metadata };
    this.logger.error(JSON.stringify(entry));
    this.writeToDatabase(entry, userId, userEmail, ipAddress, userAgent);
  }

  /**
   * Log debug message
   * @param message Debug message to log
   * @param context Optional context for categorizing the log
   * @param metadata Optional additional data for the log entry
   * @param userId Optional user UUID
   * @param userEmail Optional user email
   * @param ipAddress Optional client IP address
   * @param userAgent Optional user agent string
   */
  debug(message: string, context?: string, metadata?: Record<string, any>, userId?: string, userEmail?: string, ipAddress?: string, userAgent?: string): void {
    const entry: LogEntry = { level: LogLevel.DEBUG, message, context, metadata };
    this.logger.debug(JSON.stringify(entry));
    this.writeToDatabase(entry, userId, userEmail, ipAddress, userAgent);
  }
} 