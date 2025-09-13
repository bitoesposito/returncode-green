import { 
  Controller, 
  Get, 
  Delete, 
  Param, 
  Query, 
  Req, 
  Res, 
  UseGuards,
  ParseIntPipe,
  DefaultValuePipe,
  Logger
} from '@nestjs/common';
import { Request, Response } from 'express';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CookieAuthGuard } from '../auth/guards/cookie-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/auth.interface';
import { UserRole } from '../auth/auth.interface';
import { SecurityService } from './security.service';
import { SessionService } from '../common/services/session.service';
import { ApiResponseDto } from '../common/common.interface';
import { SessionLog } from '../common/entities/session-log.entity';

// Interface for authenticated request
interface AuthenticatedRequest extends Request {
  user: {
    uuid: string;
    email: string;
    role: string;
    sessionId?: string;
  };
}

/**
 * Security Controller
 * 
 * Provides comprehensive security management endpoints for user data privacy,
 * session management, and GDPR compliance operations.
 * 
 * Features:
 * - Security logs and activity monitoring
 * - User session management and tracking
 * - GDPR-compliant data export and download
 * - Account deletion with safety checks
 * - Session revocation and management
 * 
 * Security:
 * - All endpoints require JWT authentication
 * - Role-based access control
 * - Comprehensive audit logging
 * - IP address and user agent tracking
 * 
 * GDPR Compliance:
 * - Right to data portability (data export)
 * - Right to be forgotten (account deletion)
 * - Transparent data processing (security logs)
 * - Secure data handling and storage
 */
@Controller('security')
  @UseGuards(CookieAuthGuard, RolesGuard)
export class SecurityController {
  private readonly logger = new Logger(SecurityController.name);

  constructor(
    private readonly securityService: SecurityService,
    private readonly sessionService: SessionService,
    @InjectRepository(SessionLog)
    private readonly sessionLogRepository: Repository<SessionLog>,
  ) {}

  // ============================================================================
  // SECURITY MONITORING ENDPOINTS
  // ============================================================================

  /**
   * Get user security activity logs
   * 
   * Retrieves paginated security logs for the authenticated user.
   * Provides comprehensive transparency into user activities and security events.
   * 
   * @param req - Express request object
   * @param page - Page number for pagination (default: 1)
   * @param limit - Number of logs per page (default: 10)
   * @returns Paginated security logs
   */
  @Get('logs')
  @Roles(UserRole.user, UserRole.admin)
  async getSecurityLogs(
    @Req() req: AuthenticatedRequest,
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
    @Query('limit', new DefaultValuePipe(10), ParseIntPipe) limit: number
  ): Promise<ApiResponseDto<any>> {
    const userId = req.user['uuid'];
    return this.securityService.getSecurityLogs(userId, page, limit, req);
  }

  /**
   * Get user session information
   * 
   * Retrieves comprehensive information about the user's active and recent sessions.
   * Provides details about device usage, IP addresses, and session activity.
   * 
   * @param req - Express request object
   * @returns User session information
   */
  @Get('sessions')
  @Roles(UserRole.user, UserRole.admin)
  async getSessions(@Req() req: AuthenticatedRequest): Promise<ApiResponseDto<any>> {
    const userId = req.user['uuid'];
    return this.securityService.getSessions(userId, req);
  }

  /**
   * Get session logs for debugging
   * 
   * Retrieves session logs for debugging purposes.
   * Only available for admin users.
   * 
   * @param req - Express request object
   * @param limit - Number of logs to retrieve (default: 50)
   * @returns Session logs for debugging
   */
  @Get('debug/session-logs')
  @Roles(UserRole.admin)
  async getSessionLogs(
    @Req() req: AuthenticatedRequest,
    @Query('limit', new DefaultValuePipe(50), ParseIntPipe) limit: number
  ): Promise<ApiResponseDto<any>> {
    const userId = req.user['uuid'];
    
    // Get recent session logs
    const sessionLogs = await this.sessionLogRepository.find({
      relations: ['user'],
      order: { timestamp: 'DESC' },
      take: limit
    });

    // Format logs for debugging
    const formattedLogs = sessionLogs.map(log => ({
      id: log.id,
      timestamp: log.timestamp,
      eventType: log.eventType,
      userId: log.user?.uuid || 'NO_USER',
      userEmail: log.user?.email || 'NO_EMAIL',
      sessionId: log.details?.sessionId || 'NO_SESSION_ID',
      details: log.details,
      ipAddress: log.ipAddress,
      userAgent: log.userAgent
    }));

    return ApiResponseDto.success(
      { 
        logs: formattedLogs,
        total: formattedLogs.length,
        currentUserId: userId
      },
      'Session logs retrieved successfully'
    );
  }

  /**
   * Get active sessions in memory for debugging
   * 
   * Retrieves all active sessions currently stored in memory.
   * Only available for admin users.
   * 
   * @param req - Express request object
   * @returns Active sessions in memory
   */
  @Get('debug/active-sessions')
  @Roles(UserRole.admin)
  async getActiveSessions(@Req() req: AuthenticatedRequest): Promise<ApiResponseDto<any>> {
    const userId = req.user['uuid'];
    
    // Get session stats
    const stats = this.sessionService.getSessionStats();
    
    // Get all active sessions
    const activeSessions = this.sessionService.getAllActiveSessions();

    return ApiResponseDto.success(
      { 
        stats,
        activeSessions,
        currentUserId: userId
      },
      'Active sessions retrieved successfully'
    );
  }

  /**
   * Terminate a specific session
   * 
   * Terminates a specific user session by session ID.
   * Useful for logging out from a specific device.
   * 
   * @param sessionId - Session ID to terminate
   * @param req - Express request object
   * @returns Confirmation of session termination
   */
  @Delete('sessions/:sessionId')
  @Roles(UserRole.user, UserRole.admin)
  async terminateSession(
    @Param('sessionId') sessionId: string,
    @Req() req: AuthenticatedRequest
  ): Promise<ApiResponseDto<any>> {
    const userId = req.user['uuid'];
    
    // Verify the session belongs to the user
    const session = this.sessionService.getSession(sessionId);
    if (!session || session.userId !== userId) {
      return ApiResponseDto.error('Session not found or access denied', 404);
    }

    // Terminate the session
    await this.sessionService.invalidateSession(sessionId, 'USER_TERMINATED');
    
    return ApiResponseDto.success(
      { sessionId },
      'Session terminated successfully'
    );
  }

  /**
   * Terminate all other sessions
   * 
   * Terminates all user sessions except the current one.
   * Useful for logging out from all other devices.
   * 
   * @param req - Express request object
   * @returns Confirmation of session termination
   */
  @Delete('sessions/all')
  @Roles(UserRole.user, UserRole.admin)
  async terminateAllOtherSessions(@Req() req: AuthenticatedRequest): Promise<ApiResponseDto<any>> {
    const userId = req.user['uuid'];
    const currentSessionId = req.user['sessionId'];
    
    if (!currentSessionId) {
      return ApiResponseDto.error('Current session not found', 400);
    }

    // Terminate all other sessions
    await this.sessionService.invalidateOtherSessions(userId, currentSessionId);
    
    return ApiResponseDto.success(
      { terminatedSessions: 'all_other' },
      'All other sessions terminated successfully'
    );
  }

  // ============================================================================
  // GDPR COMPLIANCE ENDPOINTS
  // ============================================================================

  /**
   * Download user data (GDPR compliance)
   * 
   * Provides a comprehensive export of all user data for GDPR compliance.
   * Includes user profile, security logs, and session information.
   * 
   * @param req - Express request object
   * @returns Data export information
   */
  @Get('download-data')
  @Roles(UserRole.user, UserRole.admin)
  async downloadData(@Req() req: AuthenticatedRequest): Promise<ApiResponseDto<any>> {
    const userId = req.user['uuid'];
    return this.securityService.downloadData(userId, req);
  }

  



  /**
   * Delete user account (GDPR compliance)
   * 
   * Permanently deletes the user account and all associated data.
   * Implements the "right to be forgotten" under GDPR.
   * 
   * @param req - Express request object
   * @returns Confirmation of account deletion
   */
  @Delete('account')
  @Roles(UserRole.user, UserRole.admin)
  async deleteAccount(@Req() req: AuthenticatedRequest): Promise<ApiResponseDto<any>> {
    const userId = req.user['uuid'];
    return this.securityService.deleteAccount(userId, req);
  }

  /**
   * Delete user account (GDPR compliance) - Alternative endpoint
   * 
   * Permanently deletes the user account and all associated data.
   * Implements the "right to be forgotten" under GDPR.
   * 
   * @param req - Express request object
   * @returns Confirmation of account deletion
   */
  @Delete('delete-account')
  @Roles(UserRole.user, UserRole.admin)
  async deleteAccountAlternative(@Req() req: AuthenticatedRequest): Promise<ApiResponseDto<any>> {
    const userId = req.user['uuid'];
    return this.securityService.deleteAccount(userId, req);
  }
} 