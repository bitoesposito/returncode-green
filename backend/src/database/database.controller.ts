import { Controller, Get, Post } from '@nestjs/common';
import { ApiResponseDto } from '../common/common.interface';
import { DatabaseService } from './database.service';

/**
 * Database Controller
 * 
 * Provides REST API endpoints for database management and monitoring.
 * Offers administrative functions for database status checking and
 * schema synchronization.
 * 
 * Features:
 * - Database status monitoring
 * - Schema synchronization endpoints
 * - Table existence verification
 * - Database health checks
 * 
 * Endpoints:
 * - GET /database/status - Check database connection and table status
 * - POST /database/sync - Force database schema synchronization
 * 
 * Security:
 * - These endpoints should be protected in production
 * - Consider adding admin-only access control
 * - Monitor usage for security purposes
 * 
 * Usage:
 * - Used by administrators for database management
 * - Provides health check endpoints for monitoring
 * - Enables manual database synchronization when needed
 * 
 * @example
 * // Check database status
 * GET /database/status
 * Response: { status: 'connected', tables_exist: true, table_info: [...] }
 * 
 * @example
 * // Force database sync
 * POST /database/sync
 * Response: { success: true, message: 'Database synchronized successfully' }
 */
@Controller('database')
export class DatabaseController {
  constructor(
    private readonly databaseService: DatabaseService,
  ) {}

  // ============================================================================
  // DATABASE STATUS ENDPOINTS
  // ============================================================================

  /**
   * Check database status and table information
   * 
   * Provides comprehensive database health information including:
   * - Connection status
   * - Table existence verification
   * - Detailed table schema information
   * 
   * @returns Promise with database status information
   * 
   * @example
   * // Request
   * GET /database/status
   * 
   * // Response
   * {
   *   "http_status_code": 200,
   *   "success": true,
   *   "message": "Database status retrieved successfully",
   *   "data": {
   *     "status": "connected",
   *     "tables_exist": true,
   *     "table_info": [
   *       {
   *         "table_name": "auth_users",
   *         "column_name": "id",
   *         "data_type": "uuid",
   *         "is_nullable": "NO"
   *       }
   *     ]
   *   }
   * }
   */
  @Get('status')
  async getStatus(): Promise<ApiResponseDto<any>> {
    try {
      const tablesExist = await this.databaseService.checkTables();
      const tableInfo = await this.databaseService.getTableInfo();
      
      return ApiResponseDto.success({
        status: 'connected',
        tables_exist: tablesExist,
        table_info: tableInfo,
      }, 'Database status retrieved successfully');
    } catch (error) {
      return ApiResponseDto.error('Database status check failed', 500);
    }
  }

  // ============================================================================
  // DATABASE MANAGEMENT ENDPOINTS
  // ============================================================================

  /**
   * Force database schema synchronization
   * 
   * Triggers a manual database synchronization to ensure the schema
   * matches the current entity definitions. This is useful for:
   * - Development environment setup
   * - Schema updates after entity changes
   * - Recovery from schema inconsistencies
   * 
   * Warning: This operation can be destructive in production environments.
   * Use with caution and ensure proper backups.
   * 
   * @returns Promise with synchronization result
   * 
   * @example
   * // Request
   * POST /database/sync
   * 
   * // Success Response
   * {
   *   "http_status_code": 200,
   *   "success": true,
   *   "message": "Database synchronized successfully",
   *   "data": null
   * }
   * 
   * // Error Response
   * {
   *   "http_status_code": 500,
   *   "success": false,
   *   "message": "Database synchronization failed",
   *   "data": null
   * }
   */
  @Post('sync')
  async syncDatabase(): Promise<ApiResponseDto<any>> {
    try {
      const success = await this.databaseService.forceSync();
      
      if (success) {
        return ApiResponseDto.success(null, 'Database synchronized successfully');
      } else {
        return ApiResponseDto.error('Database synchronization failed', 500);
      }
    } catch (error) {
      return ApiResponseDto.error('Database synchronization failed', 500);
    }
  }
} 