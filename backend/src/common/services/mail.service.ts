import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { TemplateService, EmailTemplateType, EmailTemplateData } from './template.service';

/**
 * Interface for email sending options
 * 
 * Defines the structure for email sending requests including
 * recipient, template type, subject, and template data.
 */
export interface EmailOptions {
  /** Recipient email address */
  to: string;
  /** Type of email template to use */
  templateType: EmailTemplateType;
  /** Optional custom subject line */
  subject?: string;
  /** Data to inject into the email template */
  data: EmailTemplateData;
}

/**
 * Mail Service
 * 
 * Provides email sending functionality using SMTP and template system.
 * Handles email delivery, template processing, and SMTP configuration.
 * 
 * Features:
 * - SMTP-based email delivery
 * - Template-based email generation
 * - Automatic subject line generation
 * - Connection verification and error handling
 * - Template cache management
 * - Comprehensive logging
 * 
 * SMTP Configuration:
 * - Configurable SMTP server settings
 * - Connection timeout handling
 * - Secure authentication
 * - Connection verification on startup
 * 
 * Email Templates:
 * - Integration with TemplateService
 * - Support for verification and reset emails
 * - Automatic subject line generation
 * - Template cache management
 * 
 * Security Features:
 * - Configurable timeouts
 * - Error handling and logging
 * - Secure SMTP authentication
 * - Template injection protection
 * 
 * Usage:
 * - Injected into services that need to send emails
 * - Provides high-level email sending methods
 * - Supports template-based email generation
 * - Handles SMTP configuration automatically
 * 
 * @example
 * // Send verification email
 * await this.mailService.sendVerificationEmail('user@example.com', 'verification_token');
 * 
 * @example
 * // Send password reset email
 * await this.mailService.sendPasswordResetEmail('user@example.com', 'reset_token');
 * 
 * @example
 * // Send custom email with template
 * await this.mailService.sendEmail({
 *   to: 'user@example.com',
 *   templateType: 'verification',
 *   subject: 'Welcome to our platform!',
 *   data: { username: 'John', verificationCode: 'abc123' }
 * });
 */
@Injectable()
export class MailService {
    private readonly logger = new Logger(MailService.name);
    private transporter: nodemailer.Transporter;
    private frontendUrl: string;
    private fromEmail: string;

    constructor(
        private configService: ConfigService,
        private templateService: TemplateService
    ) {
        this.initializeTransporter();
        this.frontendUrl = this.configService.get<string>('FE_URL') || 'http://localhost:4200';
        this.fromEmail = this.configService.get<string>('SMTP_USER') || 'noreply@hashcerts.com';
    }

    // ============================================================================
    // SMTP INITIALIZATION AND CONFIGURATION
    // ============================================================================

    /**
     * Initialize SMTP transporter with configuration
     * 
     * Sets up the nodemailer transporter with SMTP settings from environment.
     * Verifies the connection to ensure email delivery will work.
     * 
     * Configuration includes:
     * - SMTP host and port
     * - Authentication credentials
     * - Connection timeouts
     * - Security settings
     * 
     * @throws Error if SMTP connection verification fails
     */
    private async initializeTransporter() {
        const smtpConfig = {
            host: this.configService.get<string>('SMTP_HOST'),
            port: this.configService.get<number>('SMTP_PORT'),
            secure: false,
            auth: {
                user: this.configService.get<string>('SMTP_USER'),
                pass: this.configService.get<string>('SMTP_PASS'),
            },
            connectionTimeout: 10000, // 10 seconds
            greetingTimeout: 10000,
            socketTimeout: 10000,
            debug: false, // Enable debug logs
            logger: false // Enable logger
        };

        this.transporter = nodemailer.createTransport(smtpConfig);

        // Verify connection configuration
        try {
            await this.transporter.verify();
            this.logger.log('SMTP connection verified successfully');
        } catch (error) {
            this.logger.error('SMTP connection verification failed:', error);
            throw error;
        }
    }

    // ============================================================================
    // EMAIL SENDING METHODS
    // ============================================================================

    /**
     * Send email using template system
     * 
     * Sends an email using the specified template and data.
     * Automatically generates subject line if not provided.
     * 
     * @param options - Email options including template type and data
     * @returns Promise that resolves when email is sent
     * @throws Error if email sending fails
     * 
     * @example
     * await this.sendEmail({
     *   to: 'user@example.com',
     *   templateType: 'verification',
     *   subject: 'Welcome!',
     *   data: { username: 'John', verificationCode: 'abc123' }
     * });
     */
    async sendEmail(options: EmailOptions): Promise<void> {
        try {
            const { to, templateType, subject, data } = options;

            // Get default subject if not provided
            const emailSubject = subject || this.getDefaultSubject(templateType);

            // Get processed template with injected data
            const html = await this.templateService.getEmailTemplate(templateType, data);

            // Send email using SMTP transporter
            await this.transporter.sendMail({
                from: this.fromEmail,
                to,
                subject: emailSubject,
                html,
            });

            this.logger.log(`Email sent successfully to ${to} using template: ${templateType}`);
        } catch (error) {
            this.logger.error(`Failed to send email to ${options.to}:`, error);
            throw error;
        }
    }

    /**
     * Send verification email
     * 
     * Sends a verification email using the verification template.
     * Automatically generates subject line and processes template.
     * 
     * @param to - Recipient email address
     * @param token - Verification token to include in email
     * @returns Promise that resolves when email is sent
     * 
     * @example
     * await this.sendVerificationEmail('user@example.com', 'verification_token_123');
     */
    async sendVerificationEmail(to: string, token: string): Promise<void> {
        await this.sendEmail({
            to,
            templateType: 'verification',
            data: {
                verificationCode: token
            }
        });
    }

    /**
     * Send password reset email
     * 
     * Sends a password reset email using the reset template.
     * Automatically generates subject line and processes template.
     * 
     * @param to - Recipient email address
     * @param token - Reset token to include in email
     * @returns Promise that resolves when email is sent
     * 
     * @example
     * await this.sendPasswordResetEmail('user@example.com', 'reset_token_456');
     */
    async sendPasswordResetEmail(to: string, token: string): Promise<void> {
        await this.sendEmail({
            to,
            templateType: 'reset',
            data: {
                resetCode: token
            }
        });
    }

    // ============================================================================
    // UTILITY METHODS
    // ============================================================================

    /**
     * Get default subject for template type
     * 
     * Returns a default subject line based on the template type.
     * Provides consistent subject lines for common email types.
     * 
     * @param templateType - Type of email template
     * @returns Default subject line for the template type
     * 
     * @example
     * const subject = this.getDefaultSubject('verification');
     * // Returns: 'Verify your email address'
     */
    private getDefaultSubject(templateType: EmailTemplateType): string {
        const subjects = {
            verification: 'Verify your email address',
            reset: 'Reset your password'
        };

        return subjects[templateType] || 'Message from Hash certs';
    }

    /**
     * Get available template types
     * 
     * Returns a list of available email template types.
     * Delegates to TemplateService for template discovery.
     * 
     * @returns Promise with array of available template names
     * 
     * @example
     * const templates = await this.getAvailableTemplates();
     * // Returns: ['verification', 'reset']
     */
    async getAvailableTemplates(): Promise<string[]> {
        return this.templateService.getAvailableTemplates();
    }

    /**
     * Clear template cache
     * 
     * Clears the template cache in TemplateService.
     * Useful for development or when templates are updated.
     * 
     * @example
     * this.clearTemplateCache();
     */
    clearTemplateCache(): void {
        this.templateService.clearCache();
    }
} 