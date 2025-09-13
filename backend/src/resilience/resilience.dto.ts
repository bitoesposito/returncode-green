// Response DTOs for RESILIENCE module
// These are interfaces since they represent response data structures

import { IsString, IsOptional, IsNumber, IsDateString } from 'class-validator';

/**
 * System Status Response DTO
 * 
 * Defines the structure for system health status responses.
 * Provides comprehensive information about the overall system health
 * and individual service statuses.
 * 
 * Status Levels:
 * - 'healthy': Service is functioning normally
 * - 'degraded': Service is experiencing issues but still operational
 * - 'down': Service is completely unavailable
 * 
 * @example
 * {
 *   "status": "healthy",
 *   "timestamp": "2024-01-15T10:30:00.000Z",
 *   "version": "1.0.0",
 *   "uptime": 86400,
 *   "services": {
 *     "database": "healthy",
 *     "storage": "healthy",
 *     "email": "degraded"
 *   }
 * }
 */
export interface SystemStatusResponseDto {
  /** Overall system health status */
  status: 'healthy' | 'degraded' | 'down';
  /** ISO timestamp of when the status was checked */
  timestamp: string;
  /** Application version */
  version: string;
  /** System uptime in seconds */
  uptime: number;
  /** Individual service health statuses */
  services: {
    /** Database service health status */
    database: 'healthy' | 'degraded' | 'down';
    /** Storage service (MinIO) health status */
    storage: 'healthy' | 'degraded' | 'down';
    /** Email service health status */
    email: 'healthy' | 'degraded' | 'down';
  };
}

/**
 * Backup Response DTO
 * 
 * Defines the structure for backup operation responses.
 * Provides information about created, restored, or available backups.
 * 
 * @example
 * {
 *   "backup_id": "2024-01-15T10-30-00-000Z",
 *   "backup_file": "backup-2024-01-15T10-30-00-000Z.sql",
 *   "backup_size": 1048576,
 *   "created_at": "2024-01-15T10:30:00.000Z",
 *   "status": "completed"
 * }
 */
export interface BackupResponseDto {
  /** Unique identifier for the backup (timestamp-based) */
  backup_id: string;
  /** Name of the backup file */
  backup_file: string;
  /** Size of the backup file in bytes */
  backup_size: number;
  /** ISO timestamp when the backup was created */
  created_at: string;
  /** Current status of the backup operation */
  status: 'completed' | 'restored' | 'available';
}

/**
 * Backup Status Response DTO
 * 
 * Provides comprehensive information about backup system status,
 * including last backup details, retention policy, and automation status.
 * 
 * @example
 * {
 *   "last_backup": {
 *     "timestamp": "2024-01-15T10:30:00.000Z",
 *     "file": "backup-2024-01-15T10-30-00-000Z.sql",
 *     "size": 1048576,
 *     "checksum_valid": true
 *   },
 *   "total_backups": 10,
 *   "total_size": 10485760,
 *   "retention_policy": {
 *     "days": 30,
 *     "next_cleanup": "2024-02-14T10:30:00.000Z"
 *   },
 *   "automation_status": {
 *     "backup_cron": "running",
 *     "cleanup_cron": "running",
 *     "verify_cron": "stopped"
 *   }
 * }
 */
export class BackupStatusResponseDto {
  /** Information about the most recent backup */
  last_backup: {
    /** ISO timestamp of the last backup */
    timestamp: string;
    /** Name of the last backup file */
    file: string;
    /** Size of the last backup in bytes */
    size: number;
    /** Whether the backup file checksum is valid */
    checksum_valid: boolean;
  } | null;
  /** Total number of available backups */
  total_backups: number;
  /** Total size of all backups in bytes */
  total_size: number;
  /** Backup retention policy configuration */
  retention_policy: {
    /** Number of days to retain backups */
    days: number;
    /** ISO timestamp of next scheduled cleanup */
    next_cleanup: string;
  };
  /** Status of automated backup processes */
  automation_status: {
    /** Status of automated backup cron job */
    backup_cron: 'running' | 'stopped';
    /** Status of automated cleanup cron job */
    cleanup_cron: 'running' | 'stopped';
    /** Status of automated verification cron job */
    verify_cron: 'running' | 'stopped';
  };
} 