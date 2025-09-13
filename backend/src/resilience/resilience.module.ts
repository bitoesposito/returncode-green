import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ResilienceController } from './resilience.controller';
import { ResilienceService } from './resilience.service';
import { User } from '../auth/entities/user.entity';
import { CommonModule } from '../common/modules/common.module';
import { MinioModule } from '../common/modules/minio.module';

/**
 * Resilience Module
 * 
 * Provides system resilience, disaster recovery, and backup management
 * functionality for the application. Ensures system availability and
 * data protection through comprehensive backup and recovery operations.
 * 
 * Features:
 * - System health monitoring and status reporting
 * - Automated database backup creation and management
 * - Backup restoration and disaster recovery
 * - Storage health monitoring (MinIO)
 * - Email service health checks
 * - Comprehensive audit logging for backup operations
 * 
 * Services:
 * - ResilienceService: Core resilience and backup operations
 * - ResilienceController: REST API endpoints for resilience management
 * 
 * Dependencies:
 * - TypeOrmModule: Database operations and entity management
 * - CommonModule: Shared services (audit, logging, etc.)
 * - MinioModule: Object storage for backup files
 * 
 * Exports:
 * - ResilienceService: For use in other modules that need backup functionality
 * 
 * Usage:
 * - Imported in AppModule for system resilience features
 * - Provides backup and recovery endpoints
 * - Handles system health monitoring
 * - Manages disaster recovery procedures
 * 
 * @example
 * // In AppModule
 * imports: [
 *   ResilienceModule,
 *   // other modules...
 * ]
 * 
 * @example
 * // In another service
 * constructor(
 *   private resilienceService: ResilienceService
 * ) {}
 * 
 * // Create backup
 * await this.resilienceService.createBackup();
 * 
 * // Check system status
 * const status = await this.resilienceService.getSystemStatus();
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    TypeOrmModule,
    CommonModule,
    MinioModule,
  ],
  controllers: [ResilienceController],
  providers: [ResilienceService],
  exports: [ResilienceService],
})
export class ResilienceModule {} 