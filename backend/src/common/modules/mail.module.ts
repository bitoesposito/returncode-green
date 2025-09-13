import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

// Local imports
import { MailService } from '../services/mail.service';
import { TemplateService } from '../services/template.service';

/**
 * Mail Module
 * 
 * Provides email functionality for the application including email sending,
 * template management, and email template rendering.
 * 
 * Features:
 * - Email sending with various providers
 * - HTML email template rendering
 * - Template caching for performance
 * - Email template management
 * - Template data validation
 * 
 * Services:
 * - MailService: Core email sending functionality
 * - TemplateService: Email template rendering and management
 * 
 * Dependencies:
 * - ConfigModule: For email configuration (SMTP settings, etc.)
 * 
 * Configuration:
 * - SMTP server settings
 * - Email provider configuration
 * - Template directory paths
 * - Email sending limits and retries
 * 
 * Usage:
 * - Imported by other modules for email functionality
 * - Used for user notifications, verification emails, etc.
 * - Provides template testing capabilities
 */
@Module({
  // Import configuration module for email settings
  imports: [ConfigModule],
  
  // Service providers for email functionality
  providers: [
    MailService,      // Core email sending service
    TemplateService,  // Email template rendering service
  ],
  
  // Export services for use in other modules
  exports: [
    MailService,      // Email sending functionality
    TemplateService,  // Template rendering functionality
  ],
})
export class MailModule {} 