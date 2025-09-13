import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

// Local imports
import { MailModule } from './mail.module';
// import { MinioModule } from './minio.module';
import { SessionModule } from './session.module';
import { ImageOptimizerModule } from './image-optimizer.module';
import { EmailController } from '../controllers/email.controller';
import { AuditService } from '../services/audit.service';
import { LoggerService } from '../services/logger.service';
import { MetricsService } from '../services/metrics.service';
import { MetricsInterceptor } from '../interceptors/metrics.interceptor';
import { AuditLog } from '../entities/audit-log.entity';
import { SecurityLog } from '../entities/security-log.entity';
import { SessionLog } from '../entities/session-log.entity';
import { User } from '../../auth/entities/user.entity';
import { GuardsModule } from '../../auth/guards/guards.module';

/**
 * Common Module
 * 
 * Central module that provides shared services and functionality across the application.
 * Aggregates common services, interceptors, and modules for reuse throughout the system.
 * 
 * Features:
 * - Email functionality (MailModule)
 * - Session management (SessionModule)
 * - Image optimization (ImageOptimizerModule)
 * - File storage (MinioModule - currently disabled)
 * - Audit logging (AuditService)
 * - Application logging (LoggerService)
 * - Metrics collection (MetricsService, MetricsInterceptor)
 * - Email template testing (EmailController)
 * 
 * Services Provided:
 * - AuditService: Security event logging and tracking
 * - LoggerService: Application logging and error tracking
 * - MetricsService: Request metrics and analytics
 * - MetricsInterceptor: Automatic metrics collection
 * 
 * Modules Imported:
 * - MailModule: Email sending and template management
 * - SessionModule: User session management
 * - ImageOptimizerModule: Image processing and optimization
 * - MinioModule: Object storage (currently disabled)
 * 
 * Exports:
 * - All imported modules for use in other parts of the application
 * - Core services for dependency injection
 * - Interceptors for global application use
 * 
 * Usage:
 * - Imported by other modules to access shared functionality
 * - Provides centralized service management
 * - Enables consistent logging and metrics across the application
 */
@Module({
  // Import sub-modules for functionality
  imports: [
    TypeOrmModule.forFeature([AuditLog, SecurityLog, SessionLog, User]),
    MailModule,              // Email functionality
    // MinioModule,          // Object storage (disabled)
    SessionModule,           // Session management
    ImageOptimizerModule,    // Image optimization
    GuardsModule,            // Authentication and guards
  ],
  
  // Controllers for this module
  controllers: [
    EmailController,         // Email template testing and management
  ],
  
  // Service providers for dependency injection
  providers: [
    AuditService,            // Security audit logging
    LoggerService,           // Application logging
    MetricsService,          // Request metrics collection
    MetricsInterceptor,      // Automatic metrics interceptor
  ],
  
  // Exports for use in other modules
  exports: [
    // Export all imported modules
    MailModule,              // Email functionality
    // MinioModule,          // Object storage (disabled)
    SessionModule,           // Session management
    ImageOptimizerModule,    // Image optimization
    
    // Export core services
    AuditService,            // Security audit logging
    LoggerService,           // Application logging
    MetricsService,          // Request metrics collection
    MetricsInterceptor,      // Automatic metrics interceptor
  ],
})
export class CommonModule {} 