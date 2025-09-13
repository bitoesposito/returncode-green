import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SecurityController } from './security.controller';
import { SecurityService } from './security.service';
import { User } from '../auth/entities/user.entity';
import { UserProfile } from '../users/entities/user-profile.entity';
import { SessionLog } from '../common/entities/session-log.entity';
import { CommonModule } from '../common/modules/common.module';
import { SessionModule } from '../common/modules/session.module';
import { GuardsModule } from '../auth/guards/guards.module';
import { MinioModule } from '../common/modules/minio.module';

/**
 * Security Module
 * 
 * Provides comprehensive security management, data privacy, and user account
 * control functionality. Implements GDPR compliance features and security
 * monitoring capabilities for user data protection and account management.
 * 
 * Features:
 * - Security logs and activity monitoring
 * - User session management and tracking
 * - GDPR-compliant data export and download
 * - Account deletion with safety checks
 * - Comprehensive audit logging for security events
 * - IP address and user agent tracking
 * - Admin account protection mechanisms
 * 
 * Services:
 * - SecurityService: Core security and privacy operations
 * - SecurityController: REST API endpoints for security management
 * 
 * Dependencies:
 * - TypeOrmModule: Database operations and entity management
 * - CommonModule: Shared services (audit, logging, etc.)
 * - User and UserProfile entities for data management
 * 
 * Security Features:
 * - JWT authentication required for all endpoints
 * - Admin account deletion protection
 * - Secure data export with expiration
 * - Comprehensive audit trails
 * - IP address and user agent tracking
 * 
 * GDPR Compliance:
 * - Right to data portability (data export)
 * - Right to be forgotten (account deletion)
 * - Transparent data processing (security logs)
 * - Secure data handling and storage
 * 
 * Exports:
 * - SecurityService: For use in other modules that need security functionality
 * 
 * Usage:
 * - Imported in AppModule for security features
 * - Provides user account management endpoints
 * - Handles GDPR compliance requirements
 * - Manages security monitoring and logging
 * 
 * @example
 * // In AppModule
 * imports: [
 *   SecurityModule,
 *   // other modules...
 * ]
 * 
 * @example
 * // In another service
 * constructor(
 *   private securityService: SecurityService
 * ) {}
 * 
 * // Get user security logs
 * const logs = await this.securityService.getSecurityLogs(userId);
 * 
 * // Download user data (GDPR)
 * const download = await this.securityService.downloadData(userId, request);
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([User, UserProfile, SessionLog]),
    CommonModule, // For AuditService
    SessionModule, // For SessionService
    GuardsModule,
    MinioModule, // For MinioService
  ],
  controllers: [SecurityController],
  providers: [SecurityService],
  exports: [SecurityService],
})
export class SecurityModule {} 