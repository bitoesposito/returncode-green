import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

// Local imports
import { ApiResponseDto } from '../common/common.interface';
import { User } from '../auth/entities/user.entity';
import { UserProfile } from '../users/entities/user-profile.entity';
import { 
  UserManagementResponseDto, 
  SystemMetricsResponseDto, 
  AuditLogsResponseDto 
} from './admin.dto';
import { AuditService, AuditEventType } from '../common/services/audit.service';
import { MetricsService } from '../common/services/metrics.service';
import { UserRole } from '../auth/auth.interface';

/**
 * Admin Service
 * 
 * Core business logic for administrative operations including:
 * - User management (listing, searching, deletion)
 * - System metrics collection and aggregation
 * - Audit log retrieval and formatting
 * - Security validation and access control
 * 
 * This service handles all administrative tasks and ensures proper
 * logging, validation, and security measures are in place.
 */
@Injectable()
export class AdminService {
  private readonly logger = new Logger(AdminService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(UserProfile)
    private readonly userProfileRepository: Repository<UserProfile>,
    private readonly auditService: AuditService,
    private readonly metricsService: MetricsService,
  ) {}

  // ============================================================================
  // USER MANAGEMENT METHODS
  // ============================================================================

  /**
   * Get users for administrative management
   * 
   * Retrieves a paginated list of users with optional search functionality.
   * Returns user information formatted for admin interface consumption.
   * 
   * Features:
   * - Pagination support
   * - Search by email or display name
   * - Only returns active users
   * - Includes profile information when available
   * 
   * @param page - Page number for pagination (default: 1)
   * @param limit - Number of users per page (default: 10)
   * @param search - Optional search term for filtering users
   * @param req - Request object for logging purposes
   * @returns Promise with user list and pagination information
   * 
   * @throws Error if database query fails
   */
  async getUsers(
    page: number = 1, 
    limit: number = 10, 
    search?: string, 
    req?: any
  ): Promise<ApiResponseDto<UserManagementResponseDto>> {
    try {
  

      const skip = (page - 1) * limit;

      // Build query with TypeORM QueryBuilder for flexibility
      const query = this.userRepository.createQueryBuilder('user')
        .leftJoinAndSelect('user.profile', 'profile')
        .where('user.is_active = :active', { active: true });

      // Add search filter if provided
      if (search && search.trim() !== '') {
        query.andWhere(
          '(user.email ILIKE :search OR profile.metadata->>\'display_name\' ILIKE :search)',
          { search: `%${search}%` }
        );
      }

      // Apply pagination and ordering
      query.skip(skip).take(limit).orderBy('user.created_at', 'DESC');

      const [users, total] = await query.getManyAndCount();

      // Transform users for admin view - only include necessary fields
      const transformedUsers = users.map(user => ({
        uuid: user.uuid,
        email: user.email,
        role: user.role,
        is_verified: user.is_verified,
        created_at: user.created_at.toISOString(),
        last_login_at: user.last_login_at?.toISOString(),
        profile: user.profile ? {
          display_name: user.profile.metadata?.display_name
        } : undefined
      }));

      const totalPages = Math.ceil(total / limit);

      const response: UserManagementResponseDto = {
        users: transformedUsers,
        pagination: {
          page,
          limit,
          total,
          total_pages: totalPages
        }
      };

              this.logger.log('Users retrieved successfully', { total });
      return ApiResponseDto.success(response, 'Users retrieved successfully');
    } catch (error) {
      this.logger.error('Failed to get users', { error: error.message });
      throw error;
    }
  }

  /**
   * Delete a user account and associated data
   * 
   * Permanently removes a user account and all associated profile data.
   * Includes comprehensive safety checks and audit logging.
   * 
   * Safety Checks:
   * - Prevents deletion of admin users
   * - Prevents self-deletion
   * - Validates user existence
   * 
   * Process:
   * 1. Validate user exists and can be deleted
   * 2. Log the deletion attempt for audit purposes
   * 3. Use transaction to ensure data consistency
   * 4. Remove profile reference, delete profile, then delete user
   * 
   * @param uuid - UUID of the user to delete
   * @param adminId - UUID of the admin performing the deletion
   * @param adminEmail - Email of the admin performing the deletion
   * @param req - Request object for IP and user agent extraction
   * @returns Promise with success confirmation
   * 
   * @throws NotFoundException if user doesn't exist
   * @throws BadRequestException if trying to delete admin or self
   * @throws Error if database operation fails
   */
  async deleteUser(
    uuid: string, 
    adminId: string, 
    adminEmail: string, 
    req?: any
  ): Promise<ApiResponseDto<null>> {
    try {
  

      // Step 1: Verify user exists and get profile information
      const user = await this.userRepository.findOne({
        where: { uuid },
        relations: ['profile']
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Step 2: Safety checks
      if (user.role === UserRole.admin) {
        throw new BadRequestException('Cannot delete admin users through admin interface');
      }

      if (user.uuid === adminId) {
        throw new BadRequestException('Cannot delete your own account');
      }

      // Step 3: Log the deletion attempt for audit purposes
      const clientIp = this.getClientIp(req);
      const userAgent = this.getUserAgent(req);
      await this.auditService.log({
        event_type: AuditEventType.USER_DELETED,
        user_id: adminId,
        user_email: adminEmail,
        ip_address: clientIp,
        user_agent: userAgent,
        status: 'SUCCESS',
        details: {
          action: 'admin_delete_user',
          targetUser: { uuid },
          targetUserEmail: user.email,
          timestamp: new Date().toISOString()
        }
      });

      // Step 4: Execute deletion in transaction for data consistency
      await this.userRepository.manager.transaction(async (transactionalEntityManager) => {
        // First, delete all session logs for this user
        await transactionalEntityManager
          .createQueryBuilder()
          .delete()
          .from('session_logs')
          .where('user_uuid = :userId', { userId: uuid })
          .execute();
        

        
        // Then delete all security logs for this user
        await transactionalEntityManager
          .createQueryBuilder()
          .delete()
          .from('security_logs')
          .where('user_uuid = :userId', { userId: uuid })
          .execute();
        

        
        // Then delete all audit logs for this user
        await transactionalEntityManager
          .createQueryBuilder()
          .delete()
          .from('audit_logs')
          .where('user_uuid = :userId', { userId: uuid })
          .execute();
        

        
        // Then remove the profile reference from the user
        await transactionalEntityManager
          .createQueryBuilder()
          .update('auth_users')
          .set({ profile_uuid: null })
          .where('uuid = :userId', { userId: uuid })
          .execute();

        // Then delete the profile if it exists
        if (user.profile) {
          await transactionalEntityManager
            .createQueryBuilder()
            .delete()
            .from('user_profiles')
            .where('uuid = :profileUuid', { profileUuid: user.profile.uuid })
            .execute();
        }

        // Finally delete the user
        await transactionalEntityManager
          .createQueryBuilder()
          .delete()
          .from('auth_users')
          .where('uuid = :userId', { userId: uuid })
          .execute();
      });

              this.logger.log('User deleted successfully', { uuid });
      return ApiResponseDto.success(null, 'User deleted successfully');
    } catch (error) {
      this.logger.error('Failed to delete user', { uuid, error: error.message });
      throw error;
    }
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Extract client IP address from request object
   * 
   * Handles various proxy configurations and headers to determine
   * the actual client IP address for audit logging purposes.
   * 
   * Priority order:
   * 1. X-Forwarded-For header (first IP in list)
   * 2. X-Real-IP header
   * 3. Connection remote address
   * 4. Socket remote address
   * 
   * @param req - Express request object
   * @returns Client IP address or 'Unknown' if not available
   */
  private getClientIp(req?: any): string {
    if (!req) return 'Unknown';
    
    const forwardedFor = req.headers?.['x-forwarded-for'] as string;
    const realIp = req.headers?.['x-real-ip'] as string;
    const remoteAddr = req.connection?.remoteAddress || req.socket?.remoteAddress;
    
    if (forwardedFor) {
      const ips = forwardedFor.split(',').map(ip => ip.trim());
      return ips[0];
    }
    
    if (realIp) {
      return realIp;
    }
    
    if (remoteAddr) {
      return remoteAddr.replace(/^::ffff:/, '');
    }
    
    return 'Unknown';
  }

  /**
   * Extract user agent string from request object
   * 
   * @param req - Express request object
   * @returns User agent string or 'Unknown' if not available
   */
  private getUserAgent(req?: any): string {
    if (!req) return 'Unknown';
    return req.headers?.['user-agent'] || 'Unknown';
  }

  // ============================================================================
  // SYSTEM METRICS METHODS
  // ============================================================================

  /**
   * Get comprehensive system metrics overview
   * 
   * Aggregates data from multiple sources to provide a complete
   * system overview for administrative monitoring.
   * 
   * Data Sources:
   * - MetricsService for system performance metrics
   * - Database for user statistics
   * - Real-time calculations for current day metrics
   * 
   * @param req - Request object for logging purposes
   * @returns Promise with system metrics data
   * 
   * @throws Error if metrics collection fails
   */
  async getMetrics(req?: any): Promise<ApiResponseDto<SystemMetricsResponseDto>> {
    try {
      this.logger.log('Getting system metrics');

      // Collect metrics from various services
      const systemMetrics = await this.metricsService.getSystemMetrics();
      const hourlyMetrics = await this.metricsService.getHourlyMetrics();
      const alerts = await this.metricsService.getAlerts();
      const userActivity = await this.metricsService.getUserActivityMetrics();

      // Get user statistics from database
      const totalUsers = await this.userRepository.count();
      
      // Calculate new users for today
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const newUsersToday = await this.userRepository
        .createQueryBuilder('user')
        .where('user.created_at >= :today', { today })
        .getCount();

      // Transform hourly metrics to request volume format
      const requestVolume = hourlyMetrics.map(metric => ({
        hour: metric.hour,
        count: metric.requests
      }));

      const response: SystemMetricsResponseDto = {
        overview: {
          total_users: totalUsers,
          active_users: userActivity.activeUsers,
          new_users_today: newUsersToday,
          total_requests: systemMetrics.totalRequests,
          error_rate: systemMetrics.errorRate
        },
        charts: {
          user_growth: userActivity.userGrowth,
          request_volume: requestVolume
        },
        alerts: alerts
      };

      this.logger.log('System metrics retrieved successfully', {
        totalRequests: systemMetrics.totalRequests,
        errorRate: systemMetrics.errorRate,
        activeUsers: userActivity.activeUsers
      });
      
      return ApiResponseDto.success(response, 'Metrics retrieved successfully');
    } catch (error) {
      this.logger.error('Failed to get system metrics', { error: error.message });
      throw error;
    }
  }

  /**
   * Get detailed system metrics for advanced monitoring
   * 
   * Provides comprehensive system metrics with additional details
   * for debugging and advanced system monitoring purposes.
   * 
   * @param req - Request object for logging purposes
   * @returns Promise with detailed metrics data
   * 
   * @throws Error if metrics collection fails
   */
  async getDetailedMetrics(req?: any): Promise<ApiResponseDto<any>> {
    try {
      this.logger.log('Getting detailed system metrics');

      const systemMetrics = await this.metricsService.getSystemMetrics();
      const hourlyMetrics = await this.metricsService.getHourlyMetrics();
      const alerts = await this.metricsService.getAlerts();

      const response = {
        system: systemMetrics,
        hourly: hourlyMetrics,
        alerts: alerts,
        timestamp: new Date().toISOString()
      };

      this.logger.log('Detailed metrics retrieved successfully');
      return ApiResponseDto.success(response, 'Detailed metrics retrieved successfully');
    } catch (error) {
      this.logger.error('Failed to get detailed metrics', { error: error.message });
      throw error;
    }
  }

  // ============================================================================
  // AUDIT LOGS METHODS
  // ============================================================================

  /**
   * Get paginated audit logs for security monitoring
   * 
   * Retrieves audit logs with pagination support for security
   * monitoring and compliance purposes.
   * 
   * Features:
   * - Pagination support for large log datasets
   * - Comprehensive log information including user details
   * - Formatted for admin interface consumption
   * 
   * @param page - Page number for pagination (default: 1)
   * @param limit - Number of logs per page (default: 50)
   * @param req - Request object for logging purposes
   * @returns Promise with audit logs and pagination information
   * 
   * @throws Error if log retrieval fails
   */
  async getAuditLogs(
    page: number = 1, 
    limit: number = 50, 
    req?: any
  ): Promise<ApiResponseDto<AuditLogsResponseDto>> {
    try {
      this.logger.log('Getting audit logs', { page, limit });

      // Get all audit logs without filtering by event type
      const allLogs = await this.auditService.getAllAuditLogs();

      // Apply pagination manually
      const skip = (page - 1) * limit;
      const paginatedLogs = allLogs.slice(skip, skip + limit);
      const total = allLogs.length;
      const totalPages = Math.ceil(total / limit);

      // Transform logs for admin view
      const transformedLogs = paginatedLogs.map(log => ({
        id: log.id || `log_${Date.now()}_${Math.random()}`,
        action: log.eventType,
        user_uuid: log.user?.uuid,
        user_email: log.userEmail,
        ip_address: log.ipAddress || 'Unknown',
        user_agent: log.userAgent || 'Unknown',
        timestamp: typeof log.timestamp === 'string' ? log.timestamp : log.timestamp.toISOString(),
        details: log.details
      }));

      const response: AuditLogsResponseDto = {
        logs: transformedLogs,
        pagination: {
          page,
          limit,
          total,
          total_pages: totalPages
        }
      };

      this.logger.log('Audit logs retrieved successfully', { total, page, totalPages });
      return ApiResponseDto.success(response, 'Audit logs retrieved successfully');
    } catch (error) {
      this.logger.error('Failed to get audit logs', { error: error.message });
      throw error;
    }
  }
} 