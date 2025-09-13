import { Controller, Get, Post, Param, HttpCode, HttpStatus, Query, Req } from '@nestjs/common';
import { ApiResponseDto } from '../common/common.interface';
import { ResilienceService } from './resilience.service';
import { BackupResponseDto, BackupStatusResponseDto } from './resilience.dto';

/**
 * Resilience Controller
 * 
 * Provides REST API endpoints for system resilience, backup management,
 * and disaster recovery operations. Handles system health monitoring,
 * backup creation, restoration, and status reporting.
 * 
 * Features:
 * - System health status monitoring
 * - Manual backup creation and management
 * - Backup restoration and disaster recovery
 * - Backup listing with pagination
 * - Comprehensive audit logging
 * 
 * Endpoints:
 * - GET /resilience/status - System health check
 * - POST /resilience/backup - Create system backup
 * - GET /resilience/backup - List available backups
 * - POST /resilience/backup/:backupId/restore - Restore from backup
 * 
 * Security:
 * - These endpoints should be protected in production
 * - Backup operations require appropriate permissions
 * - All operations are logged for audit purposes
 * 
 * Usage:
 * - Used by administrators for system maintenance
 * - Provides health check endpoints for monitoring
 * - Enables disaster recovery procedures
 * - Supports backup management workflows
 * 
 * @example
 * // Check system health
 * GET /resilience/status
 * Response: { status: 'healthy', services: { database: 'healthy', ... } }
 * 
 * @example
 * // Create backup
 * POST /resilience/backup
 * Response: { backup_id: 'timestamp', backup_file: 'backup.sql', ... }
 * 
 * @example
 * // List backups with pagination
 * GET /resilience/backup?page=1&limit=10
 * Response: { backups: [...], pagination: { page: 1, limit: 10, total: 25 } }
 */
@Controller('resilience')
export class ResilienceController {
    constructor(
        private readonly resilienceService: ResilienceService
    ) { }

    // ============================================================================
    // SYSTEM STATUS ENDPOINTS
    // ============================================================================

    /**
     * Get system health status
     * 
     * Provides comprehensive system health information including:
     * - Overall system status (healthy/degraded/down)
     * - Individual service health (database, storage, email)
     * - System uptime and version information
     * - Real-time health check results
     * 
     * @returns Promise with system status information
     * 
     * @example
     * // Request
     * GET /resilience/status
     * 
     * // Response
     * {
     *   "http_status_code": 200,
     *   "success": true,
     *   "message": "System status retrieved successfully",
     *   "data": {
     *     "status": "healthy",
     *     "timestamp": "2024-01-15T10:30:00.000Z",
     *     "version": "1.0.0",
     *     "uptime": 86400,
     *     "services": {
     *       "database": "healthy",
     *       "storage": "healthy",
     *       "email": "degraded"
     *     }
     *   }
     * }
     */
    @Get('status')
    @HttpCode(HttpStatus.OK)
    async getSystemStatus(): Promise<ApiResponseDto<any>> {
        return this.resilienceService.getSystemStatus();
    }

    // ============================================================================
    // BACKUP MANAGEMENT ENDPOINTS
    // ============================================================================

    /**
     * Create system backup
     * 
     * Triggers a manual system backup operation that:
     * - Creates a database dump using pg_dump
     * - Uploads the backup to MinIO storage
     * - Logs the backup operation for audit
     * - Returns backup metadata
     * 
     * Warning: This operation can be resource-intensive and may impact
     * system performance during backup creation.
     * 
     * @param req - Request object containing user information and headers
     * @returns Promise with backup creation result
     * 
     * @example
     * // Request
     * POST /resilience/backup
     * 
     * // Response
     * {
     *   "http_status_code": 201,
     *   "success": true,
     *   "message": "System backup created and uploaded to MinIO successfully",
     *   "data": {
     *     "backup_id": "2024-01-15T10-30-00-000Z",
     *     "backup_file": "backup-2024-01-15T10-30-00-000Z.sql",
     *     "backup_size": 1048576,
     *     "created_at": "2024-01-15T10:30:00.000Z",
     *     "status": "completed"
     *   }
     * }
     */
    @Post('backup')
    @HttpCode(HttpStatus.CREATED)
    async createBackup(@Req() req: any): Promise<ApiResponseDto<any>> {
        return this.resilienceService.createBackup(req);
    }

    /**
     * List available backups with pagination
     * 
     * Retrieves a paginated list of available system backups with:
     * - Backup metadata (ID, file name, size, creation date)
     * - Pagination information (page, limit, total count)
     * - Backup status information
     * 
     * @param page - Page number for pagination (default: 1)
     * @param limit - Number of backups per page (default: 10)
     * @returns Promise with paginated backup list
     * 
     * @example
     * // Request
     * GET /resilience/backup?page=1&limit=5
     * 
     * // Response
     * {
     *   "http_status_code": 200,
     *   "success": true,
     *   "message": "Backups retrieved successfully",
     *   "data": {
     *     "backups": [
     *       {
     *         "backup_id": "2024-01-15T10-30-00-000Z",
     *         "backup_file": "backup-2024-01-15T10-30-00-000Z.sql",
     *         "backup_size": 1048576,
     *         "created_at": "2024-01-15T10:30:00.000Z",
     *         "status": "available"
     *       }
     *     ],
     *     "pagination": {
     *       "page": 1,
     *       "limit": 5,
     *       "total": 25
     *     }
     *   }
     * }
     */
    @Get('backup')
    @HttpCode(HttpStatus.OK)
    async listBackups(
        @Query('page') page: string = '1',
        @Query('limit') limit: string = '10'
    ): Promise<ApiResponseDto<{backups: BackupResponseDto[], pagination: {page: number, limit: number, total: number}}>> {
        const pageNum = parseInt(page, 10) || 1;
        const limitNum = parseInt(limit, 10) || 10;
        return this.resilienceService.listBackups(pageNum, limitNum);
    }

    /**
     * Restore system from backup
     * 
     * Restores the system from a specified backup file. This operation:
     * - Downloads the backup from MinIO storage
     * - Restores the database using pg_restore
     * - Logs the restoration operation for audit
     * - Returns restoration status
     * 
     * Warning: This operation is destructive and will overwrite current data.
     * Ensure proper backups are available before proceeding.
     * 
     * @param backupId - Unique identifier of the backup to restore from
     * @param req - Request object containing user information and headers
     * @returns Promise with restoration result
     * 
     * @example
     * // Request
     * POST /resilience/backup/2024-01-15T10-30-00-000Z/restore
     * 
     * // Response
     * {
     *   "http_status_code": 200,
     *   "success": true,
     *   "message": "System restored from backup successfully",
     *   "data": {
     *     "backup_id": "2024-01-15T10-30-00-000Z",
     *     "backup_file": "backup-2024-01-15T10-30-00-000Z.sql",
     *     "backup_size": 1048576,
     *     "created_at": "2024-01-15T10:30:00.000Z",
     *     "status": "restored"
     *   }
     * }
     */
    @Post('backup/:backupId/restore')
    @HttpCode(HttpStatus.OK)
    async restoreBackup(@Param('backupId') backupId: string, @Req() req: any): Promise<ApiResponseDto<any>> {
        return this.resilienceService.restoreBackup(backupId, req);
    }
} 