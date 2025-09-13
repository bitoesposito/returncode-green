import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ApiResponseDto } from '../common/common.interface';
import { User } from '../auth/entities/user.entity';
import { UserProfile } from '../users/entities/user-profile.entity';
import { SecurityLogsResponseDto, SessionsResponseDto, DownloadDataResponseDto, DownloadData } from './security.dto';
import { AuditService, AuditEventType } from '../common/services/audit.service';
import { Request, Response } from 'express';
import { UserRole } from '../auth/auth.interface';
import { MinioService } from '../common/services/minio.service';
import * as archiver from 'archiver';

/**
 * Security Service
 * 
 * Core service responsible for security management, data privacy, and GDPR
 * compliance operations. Provides comprehensive security monitoring, user
 * session management, data export capabilities, and account lifecycle management.
 * 
 * Features:
 * - Security logs and activity monitoring
 * - User session tracking and management
 * - GDPR-compliant data export and download
 * - Account deletion with safety checks
 * - Comprehensive audit logging
 * - IP address and user agent tracking
 * - Admin account protection mechanisms
 * 
 * Security Features:
 * - All operations are logged for audit purposes
 * - IP address and user agent tracking
 * - Admin account deletion protection
 * - Secure data export with expiration
 * - Foreign key constraint handling
 * 
 * GDPR Compliance:
 * - Right to data portability (Article 20)
 * - Right to be forgotten (Article 17)
 * - Transparent data processing
 * - Secure data handling and storage
 * 
 * Dependencies:
 * - TypeORM repositories for data access
 * - AuditService for comprehensive logging
 * - Express Request/Response for HTTP handling
 * 
 * Storage:
 * - In-memory storage for download data (should use Redis in production)
 * - Database storage for user and profile data
 * - Audit logs for security events
 * 
 * Usage:
 * - Injected into SecurityController for API endpoints
 * - Used for security monitoring and compliance
 * - Provides account management functionality
 * - Handles GDPR compliance requirements
 * 
 * @example
 * // Get security logs
 * const logs = await securityService.getSecurityLogs(userId, 1, 10, request);
 * 
 * @example
 * // Download user data (GDPR)
 * const download = await securityService.downloadData(userId, request);
 * 
 * @example
 * // Delete account
 * const result = await securityService.deleteAccount(userId);
 */
@Injectable()
export class SecurityService {
  private readonly logger = new Logger(SecurityService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(UserProfile)
    private readonly userProfileRepository: Repository<UserProfile>,
    private readonly auditService: AuditService,
    private readonly minioService: MinioService,
  ) { }

  // ============================================================================
  // SECURITY MONITORING METHODS
  // ============================================================================

  /**
   * Get user security activity logs
   * 
   * Retrieves paginated security logs for a specific user from the audit system.
   * Provides comprehensive transparency into user activities and security events
   * for compliance and monitoring purposes.
   * 
   * Process:
   * 1. Validates user exists in the system
   * 2. Retrieves all audit logs for the user
   * 3. Applies pagination to the results
   * 4. Transforms audit logs to security log format
   * 5. Returns paginated security logs with metadata
   * 
   * Features:
   * - Pagination support for large log collections
   * - Comprehensive activity tracking
   * - IP address and user agent information
   * - Success/failure status for each event
   * - Detailed event information and metadata
   * 
   * @param userId - Unique identifier of the user
   * @param page - Page number for pagination (1-based, default: 1)
   * @param limit - Number of logs per page (default: 10)
   * @param req - Request object for IP and user agent extraction
   * @returns Promise<ApiResponseDto<SecurityLogsResponseDto>> Paginated security logs
   * 
   * @example
   * const logs = await securityService.getSecurityLogs('user-uuid', 1, 10, request);
   * // Returns: { logs: [...], pagination: { page: 1, limit: 10, total: 150, total_pages: 15 } }
   * 
   * @throws NotFoundException if user not found
   * @throws Error if audit log retrieval fails
   */
  async getSecurityLogs(userId: string, page: number = 1, limit: number = 10, req?: Request): Promise<ApiResponseDto<SecurityLogsResponseDto>> {
    try {
  

      // Verify user exists in the system
      const user = await this.userRepository.findOne({
        where: { uuid: userId }
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Get all audit logs for this user (no limit to get total count)
      const allAuditLogs = await this.auditService.getUserAuditLogs(userId, 10000);

      // Apply pagination to the results
      const skip = (page - 1) * limit;
      const paginatedLogs = allAuditLogs.slice(skip, skip + limit);
      const total = allAuditLogs.length;
      const totalPages = Math.ceil(total / limit);

      // Transform audit logs to security logs format for consistency
      const securityLogs = paginatedLogs.map(log => ({
        id: log.id || `log_${Date.now()}_${Math.random()}`,
        action: log.eventType,
        ip_address: log.ipAddress || 'Unknown',
        user_agent: log.userAgent || 'Unknown',
        timestamp: typeof log.timestamp === 'string' ? log.timestamp : log.timestamp.toISOString(),
        success: log.status === 'SUCCESS',
        details: log.details || {}
      }));

      const response: SecurityLogsResponseDto = {
        logs: securityLogs,
        pagination: {
          page,
          limit,
          total,
          total_pages: totalPages
        }
      };

              this.logger.log('Security logs retrieved successfully', { userId });
      
      return ApiResponseDto.success(response, 'Security logs retrieved successfully');
    } catch (error) {
      this.logger.error('Failed to get security logs', { userId, error: error.message });
      throw error;
    }
  }

  /**
   * Get user session information
   * 
   * Retrieves comprehensive information about the user's active and recent sessions.
   * Provides details about device usage, IP addresses, and session activity
   * for security monitoring and account management.
   * 
   * Process:
   * 1. Validates user exists in the system
   * 2. Extracts current session information from user data
   * 3. Retrieves recent login activities from audit logs
   * 4. Combines current and historical session data
   * 5. Returns comprehensive session information
   * 
   * Features:
   * - Current active session details
   * - Recent login history and patterns
   * - Device and browser information
   * - IP address tracking and geolocation
   * - Session expiration and activity timestamps
   * 
   * @param userId - Unique identifier of the user
   * @param req - Request object for current session information
   * @returns Promise<ApiResponseDto<SessionsResponseDto>> User session information
   * 
   * @example
   * const sessions = await securityService.getSessions('user-uuid', request);
   * // Returns: { sessions: [{ id: 'current', device_info: '...', ip_address: '...', ... }] }
   * 
   * @throws NotFoundException if user not found
   * @throws Error if session data retrieval fails
   */
  async getSessions(userId: string, req?: Request): Promise<ApiResponseDto<SessionsResponseDto>> {
    try {
  

      // Verify user exists in the system
      const user = await this.userRepository.findOne({
        where: { uuid: userId }
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Extract current session information from request
      const clientIp = this.getClientIp(req);
      const userAgent = req?.headers['user-agent'] || 'Unknown';

      // Initialize sessions array
      const sessions: any[] = [];

      // Add current active session (user is authenticated via cookie)
      sessions.push({
        id: 'current',
        device: 'Current Session',
        ip_address: clientIp,
        user_agent: userAgent,
        created_at: user.last_login_at?.toISOString() || new Date().toISOString(),
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days from now
        is_active: true
      });

      // Get recent login activities from audit logs for historical context
      const loginLogs = await this.auditService.getAuditLogsByType(AuditEventType.USER_LOGIN_SUCCESS, 10);

      // Add recent login sessions (excluding current session)
      loginLogs.forEach((log, index) => {
        if (log.user?.uuid === userId && index > 0) { // Skip current session
          sessions.push({
            id: `session_${log.id || index}`,
            device: log.details?.device || 'Unknown Device',
            ip_address: log.ipAddress || 'Unknown',
            user_agent: log.userAgent || 'Unknown',
            created_at: typeof log.timestamp === 'string' ? log.timestamp : log.timestamp.toISOString(),
            expires_at: new Date((typeof log.timestamp === 'string' ? new Date(log.timestamp) : log.timestamp).getTime() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
            is_active: false
          });
        }
      });

      const response: SessionsResponseDto = {
        sessions: sessions
      };

              this.logger.log('User sessions retrieved successfully', { userId });
      
      return ApiResponseDto.success(response, 'Sessions retrieved successfully');
    } catch (error) {
      this.logger.error('Failed to get user sessions', { userId, error: error.message });
      throw error;
    }
  }

  // ============================================================================
  // GDPR COMPLIANCE METHODS
  // ============================================================================

  /**
   * Initiate GDPR data export
   * 
   * Creates a secure download link for user data export in compliance with
   * GDPR Article 20 (Right to Data Portability). The download link expires
   * after 24 hours for security purposes.
   * 
   * Process:
   * 1. Validates user exists and retrieves complete user data
   * 2. Prepares comprehensive user data for export
   * 3. Generates secure download link with expiration
   * 4. Stores data temporarily in memory (should use Redis in production)
   * 5. Logs the export activity for audit purposes
   * 
   * Exported data includes:
   * - Complete user account information
   * - User profile data and metadata
   * - Security activity logs and audit trail
   * - Account metadata and timestamps
   * - Export information and compliance details
   * 
   * Security:
   * - Download links expire after 24 hours
   * - Data is temporarily stored in memory
   * - All export activities are logged for audit
   * - IP address and user agent are tracked
   * - Secure URL generation with timestamp
   * 
   * @param userId - Unique identifier of the user
   * @param req - Request object for audit logging
   * @returns Promise<ApiResponseDto<DownloadDataResponseDto>> Secure download information
   * 
   * @example
   * const download = await securityService.downloadData('user-uuid', request);
   * // Returns: { download_url: "...", expires_at: "...", file_size: 2048, format: "json" }
   * 
   * @throws NotFoundException if user not found
   * @throws Error if data preparation fails
   */
  async downloadData(userId: string, req: Request): Promise<ApiResponseDto<DownloadDataResponseDto>> {
    // Extract user context for audit logging
    const clientIp = this.getClientIp(req);
    const userAgent = this.getUserAgent(req);
    
    try {
  

      // Verify user exists and retrieve complete user data
      const user = await this.userRepository.findOne({
        where: { uuid: userId },
        relations: ['profile']
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Prepare comprehensive user data for GDPR export
      const userData = {
        user: {
          uuid: user.uuid,
          email: user.email,
          role: user.role,
          is_active: user.is_active,
          is_verified: user.is_verified,
          is_configured: user.is_configured,
          created_at: user.created_at,
          updated_at: user.updated_at,
          last_login_at: user.last_login_at
        },
        profile: user.profile ? {
          uuid: user.profile.uuid,
          tags: user.profile.tags,
          metadata: user.profile.metadata,
          created_at: user.profile.created_at,
          updated_at: user.profile.updated_at
        } : null,
        security_logs: await this.getUserSecurityLogsForExport(userId),
        export_info: {
          exported_at: new Date().toISOString(),
          exported_by: userId,
          format: 'json'
        }
      };

      // Generate unique timestamp and expiration for the download
      const timestamp = Date.now();
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Convert data to CSV
      const csvData = this.convertToCSV(userData);
      const csvBuffer = Buffer.from(csvData, 'utf-8');
      
      // Create ZIP archive containing the CSV
      const zipBuffer = await this.createZipArchive(user.uuid, csvBuffer);
      
      // Save ZIP file to MinIO in a dedicated directory
      const filename = `user-data-${user.uuid}-${timestamp}.zip`;
      const objectName = `exports/${filename}`;
      

      
      try {
        // Create a file-like object for upload
        const fileObject = {
          buffer: zipBuffer,
          mimetype: 'application/zip',
          originalname: filename,
          size: zipBuffer.length
        } as Express.Multer.File;

        // Upload ZIP file to MinIO
        await this.minioService.uploadFile(fileObject, objectName);
        

        
        // Generate signed MinIO URL for direct download
        const downloadUrl = await this.minioService.getSignedDownloadUrl(objectName, 24 * 60 * 60); // 24 hours

      // Log the data download activity for audit compliance
      await this.auditService.log({
        event_type: AuditEventType.DATA_DOWNLOAD,
        user_id: user.uuid,
        user_email: user.email,
        ip_address: clientIp,
        user_agent: userAgent,
        status: 'SUCCESS',
        details: {
          resource: 'user_data',
          file_size: zipBuffer.length,
          format: 'zip',
          expires_at: expiresAt.toISOString(),
          timestamp: new Date().toISOString()
        }
      });

      const response: DownloadDataResponseDto = {
        download_url: downloadUrl,
        expires_at: expiresAt.toISOString(),
        file_size: zipBuffer.length,
        format: 'zip'
      };

      this.logger.log('Data download initiated successfully', { userId: user.uuid });
      
      return ApiResponseDto.success(response, 'Data download initiated successfully');
      } catch (error) {
        this.logger.error('Failed to save file to MinIO', { userId: user.uuid, error: error.message });
        
        // Log the failed data download attempt
        await this.auditService.log({
          event_type: AuditEventType.DATA_DOWNLOAD,
          user_id: user.uuid,
          user_email: user.email,
          ip_address: clientIp,
          user_agent: userAgent,
          status: 'FAILED',
          details: {
            resource: 'user_data',
            error: error.message,
            timestamp: new Date().toISOString()
          }
        });
        
        throw new Error('Failed to create download file');
      }
    } catch (error) {
      this.logger.error('Failed to initiate data download', { userId: userId || 'undefined', error: error.message });
      
      // Log the failed data download attempt (user might not be available in this context)
      try {
        const user = await this.userRepository.findOne({
          where: { uuid: userId }
        });
        
        if (user) {
          await this.auditService.log({
            event_type: AuditEventType.DATA_DOWNLOAD,
            user_id: user.uuid,
            user_email: user.email,
            ip_address: clientIp,
            user_agent: userAgent,
            status: 'FAILED',
            details: {
              resource: 'user_data',
              error: error.message,
              timestamp: new Date().toISOString()
            }
          });
        }
      } catch (auditError) {
        this.logger.error('Failed to log audit event for failed download', { auditError: auditError.message });
      }
      
      throw error;
    }
  }



  /**
   * Convert user data to CSV format
   */
  private convertToCSV(data: any): string {
    const csvRows: string[] = [];
    
    // Add user information
    csvRows.push('Section,Field,Value');
    csvRows.push('User,UUID,' + this.escapeCSV(data.user.uuid));
    csvRows.push('User,Email,' + this.escapeCSV(data.user.email));
    csvRows.push('User,Role,' + this.escapeCSV(data.user.role));
    csvRows.push('User,Is Active,' + this.escapeCSV(data.user.is_active.toString()));
    csvRows.push('User,Is Verified,' + this.escapeCSV(data.user.is_verified.toString()));
    csvRows.push('User,Is Configured,' + this.escapeCSV(data.user.is_configured.toString()));
    csvRows.push('User,Created At,' + this.escapeCSV(data.user.created_at));
    csvRows.push('User,Updated At,' + this.escapeCSV(data.user.updated_at));
    csvRows.push('User,Last Login At,' + this.escapeCSV(data.user.last_login_at));
    
    // Add profile information
    if (data.profile) {
      csvRows.push('Profile,UUID,' + this.escapeCSV(data.profile.uuid));
      csvRows.push('Profile,Tags,' + this.escapeCSV(data.profile.tags?.join(', ') || ''));
      csvRows.push('Profile,Created At,' + this.escapeCSV(data.profile.created_at));
      csvRows.push('Profile,Updated At,' + this.escapeCSV(data.profile.updated_at));
    }
    
    // Add security logs
    if (data.security_logs && data.security_logs.length > 0) {
      csvRows.push(''); // Empty row for separation
      csvRows.push('Security Logs');
      csvRows.push('ID,Event Type,Timestamp,Status,IP Address,User Agent,Details');
      
      data.security_logs.forEach((log: any) => {
        const details = log.details ? JSON.stringify(log.details) : '';
        csvRows.push([
          this.escapeCSV(log.id),
          this.escapeCSV(log.eventType),
          this.escapeCSV(log.timestamp),
          this.escapeCSV(log.status),
          this.escapeCSV(log.ipAddress),
          this.escapeCSV(log.userAgent),
          this.escapeCSV(details)
        ].join(','));
      });
      }

    // Add export info
    csvRows.push(''); // Empty row for separation
    csvRows.push('Export Information');
    csvRows.push('Exported At,' + this.escapeCSV(data.export_info.exported_at));
    csvRows.push('Exported By,' + this.escapeCSV(data.export_info.exported_by));
    csvRows.push('Format,' + this.escapeCSV(data.export_info.format));
    
    return csvRows.join('\n');
  }

  /**
   * Escape CSV values to handle commas, quotes, and newlines
   */
  private escapeCSV(value: string): string {
    if (value === null || value === undefined) {
      return '';
    }
    
    const stringValue = String(value);
    
    // If the value contains comma, quote, or newline, wrap it in quotes
    if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
      // Escape quotes by doubling them
      const escapedValue = stringValue.replace(/"/g, '""');
      return `"${escapedValue}"`;
    }
    
    return stringValue;
  }

  /**
   * Create ZIP archive from file buffer
   * 
   * Creates a ZIP archive containing the specified file.
   * 
   * @param userId - User ID for filename generation
   * @param fileBuffer - File content as buffer
   * @returns Promise with ZIP buffer
   */
  private async createZipArchive(userId: string, fileBuffer: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const archive = archiver('zip', {
        zlib: { level: 9 } // Maximum compression
      });
      
      const chunks: Buffer[] = [];
      
      archive.on('data', (chunk) => {
        chunks.push(chunk);
      });
      
      archive.on('end', () => {
        const zipBuffer = Buffer.concat(chunks);
        resolve(zipBuffer);
      });
      
      archive.on('error', (err) => {
        reject(err);
      });
      
      // Create filename for the CSV inside the ZIP
      const csvFilename = `user-data-${userId}.csv`;
      
      // Add file to archive
      archive.append(fileBuffer, { name: csvFilename });
      
      // Finalize the archive
      archive.finalize();
    });
  }



  // ============================================================================
  // ACCOUNT MANAGEMENT METHODS
  // ============================================================================

  /**
   * Delete user account permanently
   * 
   * Permanently deletes the user account and all associated data in compliance
   * with GDPR Article 17 (Right to be Forgotten). This operation is irreversible
   * and will remove all user data from the system.
   * 
   * Safety Checks:
   * - Prevents deletion of the last admin user
   * - Validates user existence before deletion
   * - Handles foreign key constraints properly
   * - Logs deletion attempt for audit purposes
   * - Calculates account age for audit trail
   * 
   * Process:
   * 1. Validates user exists and is not the last admin
   * 2. Logs deletion attempt for audit compliance
   * 3. Uses database transaction for data integrity
   * 4. Removes profile reference from user
   * 5. Deletes user profile if exists
   * 6. Deletes user account
   * 7. Returns success confirmation
   * 
   * Warning: This operation is irreversible and will permanently delete
   * all user data including profile, security logs, and account information.
   * 
   * @param userId - Unique identifier of the user to delete
   * @param req - Express request object for IP and user agent extraction
   * @returns Promise<ApiResponseDto<null>> Deletion confirmation
   * 
   * @example
   * const result = await securityService.deleteAccount('user-uuid');
   * // Returns: { success: true, message: "Account deleted successfully", data: null }
   * 
   * @throws NotFoundException if user not found
   * @throws BadRequestException if attempting to delete the last admin user
   * @throws Error if deletion process fails
   */
  async deleteAccount(userId: string, req?: Request): Promise<ApiResponseDto<null>> {
    try {
  

      // Verify user exists and retrieve complete user data
      const user = await this.userRepository.findOne({
        where: { uuid: userId },
        relations: ['profile']
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Check if user is admin and if it's the last admin (safety check)
      if (user.role === UserRole.admin) {
        const adminCount = await this.userRepository.count({
          where: { role: UserRole.admin }
        });



        // Prevent deletion of the last admin user
        if (adminCount <= 1) {
          this.logger.warn('Attempted to delete the last admin user', { 
            userId: user.uuid, 
            userEmail: user.email, 
            adminCount 
          });
          
          // Log the failed deletion attempt for audit
          await this.auditService.log({
            event_type: AuditEventType.SUSPICIOUS_ACTIVITY,
            user_id: user.uuid,
            user_email: user.email,
            ip_address: this.getClientIp(req),
            user_agent: this.getUserAgent(req),
            status: 'WARNING',
            details: {
              activity: 'Attempted to delete last admin user',
              admin_count: adminCount,
              timestamp: new Date().toISOString()
            }
          });
          
          throw new BadRequestException('Cannot delete the last admin user. At least one admin must remain in the system.');
        }


      }

      // Log the account deletion attempt for audit compliance
      await this.auditService.log({
        event_type: AuditEventType.USER_DELETED,
        user_id: user.uuid,
        user_email: user.email,
        status: 'SUCCESS',
        details: {
          deletion_requested_at: new Date().toISOString(),
          account_age_days: Math.floor((Date.now() - user.created_at.getTime()) / (1000 * 60 * 60 * 24))
        }
      });

      // Use database transaction to handle foreign key constraints properly
      await this.userRepository.manager.transaction(async (transactionalEntityManager) => {
        // First, delete all session logs for this user
        await transactionalEntityManager
          .createQueryBuilder()
          .delete()
          .from('session_logs')
          .where('user_uuid = :userId', { userId: user.uuid })
          .execute();
        

        
        // Then delete all security logs for this user
        await transactionalEntityManager
          .createQueryBuilder()
          .delete()
          .from('security_logs')
          .where('user_uuid = :userId', { userId: user.uuid })
          .execute();
        

        
        // Then delete all audit logs for this user
        await transactionalEntityManager
          .createQueryBuilder()
          .delete()
          .from('audit_logs')
          .where('user_uuid = :userId', { userId: user.uuid })
          .execute();
        

        
        // Then remove the profile reference from the user
        await transactionalEntityManager
          .createQueryBuilder()
          .update('auth_users')
          .set({ profile_uuid: null })
          .where('uuid = :userId', { userId: user.uuid })
          .execute();
        

        
        // Then delete the profile if it exists
        if (user.profile) {
          try {
            await transactionalEntityManager
              .createQueryBuilder()
              .delete()
              .from('user_profiles')
              .where('uuid = :profileUuid', { profileUuid: user.profile.uuid })
              .execute();
            

          } catch (profileError) {
            // Profile might not exist, which is fine
            this.logger.debug('Profile deletion skipped', { 
              userId: user.uuid, 
              profileUuid: user.profile.uuid,
              error: profileError.message 
            });
          }
        }
        
        // Finally delete the user account
        await transactionalEntityManager
          .createQueryBuilder()
          .delete()
          .from('auth_users')
          .where('uuid = :userId', { userId: user.uuid })
          .execute();
        

      });
      
      this.logger.log('User account deleted successfully', { userId: user.uuid });
      
      return ApiResponseDto.success(null, 'Account deleted successfully');
    } catch (error) {
      this.logger.error('Failed to delete user account', { userId: userId || 'undefined', error: error.message });
      throw error;
    }
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Extract client IP address from request
   * 
   * Handles various proxy configurations and headers to determine the actual
   * client IP address for security logging and audit purposes.
   * 
   * Priority order:
   * 1. X-Forwarded-For header (first IP in chain)
   * 2. X-Real-IP header
   * 3. Connection remote address
   * 4. Fallback to 'Unknown'
   * 
   * @param req - Express request object containing headers and connection info
   * @returns string Client IP address or 'Unknown'
   * 
   * @example
   * const ip = this.getClientIp(request);
   * // Returns: "192.168.1.100" or "Unknown"
   */
  private getClientIp(req?: Request): string {
    if (!req) return 'Unknown';
    
    // Get IP from various headers and sources
    const forwardedFor = req.headers['x-forwarded-for'] as string;
    const realIp = req.headers['x-real-ip'] as string;
    const remoteAddr = req.connection?.remoteAddress || req.socket?.remoteAddress;
    
    // If we have X-Forwarded-For, take the first IP (original client)
    if (forwardedFor) {
      const ips = forwardedFor.split(',').map(ip => ip.trim());
      return ips[0];
    }
    
    // If we have X-Real-IP, use it
    if (realIp) {
      return realIp;
    }
    
    // If we have remote address, clean it up
    if (remoteAddr) {
      // Remove IPv6 prefix if present (::ffff:)
      return remoteAddr.replace(/^::ffff:/, '');
    }
    
    return 'Unknown';
  }

  /**
   * Extract user agent from request
   * 
   * Retrieves the user agent string from the request headers for
   * security logging and device identification purposes.
   * 
   * @param req - Express request object containing headers
   * @returns string User agent string or 'Unknown'
   * 
   * @example
   * const userAgent = this.getUserAgent(request);
   * // Returns: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..." or "Unknown"
   */
  private getUserAgent(req?: Request): string {
    if (!req) return 'Unknown';
    return req.headers['user-agent'] || 'Unknown';
  }

  /**
   * Get user security logs for data export
   * 
   * Retrieves security logs specifically formatted for GDPR data export.
   * Provides a comprehensive audit trail of user activities for compliance.
   * 
   * @param userId - Unique identifier of the user
   * @returns Promise<any[]> Formatted security logs for export
   * 
   * @example
   * const logs = await this.getUserSecurityLogsForExport('user-uuid');
   * // Returns: [{ id: "...", event_type: "...", timestamp: "...", ... }]
   */
  private async getUserSecurityLogsForExport(userId: string): Promise<any[]> {
    try {
      // Get all audit logs for this user (limited to 1000 for export)
      const auditLogs = await this.auditService.getUserAuditLogs(userId, 1000);
      
      // Format logs for GDPR export
      return auditLogs.map(log => ({
        id: log.id,
        eventType: log.eventType,
        timestamp: typeof log.timestamp === 'string' ? log.timestamp : log.timestamp.toISOString(),
        status: log.status,
        ipAddress: log.ipAddress,
        userAgent: log.userAgent,
        details: log.details
      }));
    } catch (error) {
      this.logger.error('Failed to get user security logs for export', { userId, error: error.message });
      return [];
    }
  }
} 