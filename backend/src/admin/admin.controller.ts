import { 
  Controller, 
  Get, 
  Put, 
  Delete, 
  Param, 
  HttpCode, 
  HttpStatus, 
  UseGuards, 
  Req, 
  Query 
} from '@nestjs/common';
import { Request } from 'express';

// Local imports
import { CookieAuthGuard } from '../auth/guards/cookie-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles, UserRole } from '../auth/auth.interface';
import { ApiResponseDto } from '../common/common.interface';
import { AdminService } from './admin.service';

/**
 * Interface for authenticated admin request
 * 
 * Extends the Express Request interface to include user information
 * that is added by the JWT authentication guard.
 */
interface AuthenticatedAdminRequest extends Request {
  user: {
    /** Unique identifier for the authenticated user */
    uuid: string;
    /** Email address of the authenticated user */
    email: string;
    /** Role of the authenticated user */
    role: string;
  };
}

/**
 * Admin Controller
 * 
 * Handles all administrative endpoints for the application.
 * Provides functionality for user management, system monitoring,
 * and audit log access.
 * 
 * Security:
 * - All endpoints require JWT authentication
 * - All endpoints require admin role
 * - Uses JwtAuthGuard and RolesGuard for protection
 * 
 * Endpoints:
 * - GET /admin/users - List and search users
 * - DELETE /admin/users/:uuid - Delete user account
 * - GET /admin/metrics - System metrics overview
 * - GET /admin/metrics/detailed - Detailed system metrics
 * - GET /admin/audit-logs - View audit logs
 */
@Controller('admin')
  @UseGuards(CookieAuthGuard, RolesGuard)
@Roles(UserRole.admin)
export class AdminController {
  constructor(
    private readonly adminService: AdminService
  ) {}

  // ============================================================================
  // USER MANAGEMENT ENDPOINTS
  // ============================================================================

  /**
   * Get users for administration
   * 
   * Retrieves a paginated list of users with optional search functionality.
   * Returns user information suitable for admin management interface.
   * 
   * @param page - Page number for pagination (default: 1)
   * @param limit - Number of users per page (default: 10)
   * @param search - Optional search term for email or display name
   * @param req - Authenticated request object
   * @returns Promise with user list and pagination info
   * 
   * @example
   * GET /admin/users?page=1&limit=20&search=john@example.com
   */
  @Get('users')
  async getUsers(
    @Query('page') page: string = '1',
    @Query('limit') limit: string = '10',
    @Query('search') search: string | undefined,
    @Req() req: AuthenticatedAdminRequest
  ): Promise<ApiResponseDto<any>> {
    return this.adminService.getUsers(
      parseInt(page), 
      parseInt(limit), 
      search, 
      req
    );
  }

  /**
   * Delete a user account
   * 
   * Permanently removes a user account and associated profile data.
   * Includes safety checks to prevent deletion of admin users and self-deletion.
   * 
   * @param uuid - UUID of the user to delete
   * @param req - Authenticated request object
   * @returns Promise with success confirmation
   * 
   * @example
   * DELETE /admin/users/123e4567-e89b-12d3-a456-426614174000
   */
  @Delete('users/:uuid')
  @HttpCode(HttpStatus.OK)
  async deleteUser(
    @Param('uuid') uuid: string,
    @Req() req: AuthenticatedAdminRequest
  ): Promise<ApiResponseDto<null>> {
    return this.adminService.deleteUser(
      uuid, 
      req.user.uuid, 
      req.user.email, 
      req
    );
  }

  // ============================================================================
  // SYSTEM METRICS ENDPOINTS
  // ============================================================================

  /**
   * Get system metrics overview
   * 
   * Retrieves high-level system metrics including user statistics,
   * request volumes, error rates, and system alerts.
   * 
   * @param req - Authenticated request object
   * @returns Promise with system metrics data
   * 
   * @example
   * GET /admin/metrics
   */
  @Get('metrics')
  async getMetrics(
    @Req() req: AuthenticatedAdminRequest
  ): Promise<ApiResponseDto<any>> {
    return this.adminService.getMetrics(req);
  }

  /**
   * Get detailed system metrics
   * 
   * Retrieves comprehensive system metrics with additional details
   * for advanced monitoring and debugging purposes.
   * 
   * @param req - Authenticated request object
   * @returns Promise with detailed metrics data
   * 
   * @example
   * GET /admin/metrics/detailed
   */
  @Get('metrics/detailed')
  async getDetailedMetrics(
    @Req() req: AuthenticatedAdminRequest
  ): Promise<ApiResponseDto<any>> {
    return this.adminService.getDetailedMetrics(req);
  }

  // ============================================================================
  // AUDIT LOGS ENDPOINTS
  // ============================================================================

  /**
   * Get audit logs
   * 
   * Retrieves paginated audit logs for security monitoring and
   * compliance purposes. Includes all system activities and user actions.
   * 
   * @param page - Page number for pagination (default: 1)
   * @param limit - Number of logs per page (default: 50)
   * @param req - Authenticated request object
   * @returns Promise with audit logs and pagination info
   * 
   * @example
   * GET /admin/audit-logs?page=1&limit=100
   */
  @Get('audit-logs')
  async getAuditLogs(
    @Query('page') page: string = '1',
    @Query('limit') limit: string = '50',
    @Req() req: AuthenticatedAdminRequest
  ): Promise<ApiResponseDto<any>> {
    return this.adminService.getAuditLogs(
      parseInt(page), 
      parseInt(limit), 
      req
    );
  }
} 