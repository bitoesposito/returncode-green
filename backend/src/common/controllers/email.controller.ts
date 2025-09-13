import { 
  Controller, 
  Get, 
  Post, 
  Body, 
  HttpCode, 
  HttpStatus, 
  UseGuards 
} from '@nestjs/common';

// Local imports
import { CookieAuthGuard } from '../../auth/guards/cookie-auth.guard';
import { MailService } from '../services/mail.service';
import { TemplateService, EmailTemplateData } from '../services/template.service';
import { ApiResponseDto } from '../common.interface';

/**
 * Data Transfer Object for email testing
 * 
 * Used for testing email templates with custom data.
 * Allows developers to test email functionality with different templates.
 */
interface TestEmailDto {
  /** Recipient email address */
  to: string;
  /** Type of email template to test */
  templateType: 'verification' | 'reset';
  /** Template data for email personalization */
  data: EmailTemplateData;
}

/**
 * Email Controller
 * 
 * Handles email template management and testing functionality.
 * Provides endpoints for template management and email testing.
 * 
 * Features:
 * - Email template listing
 * - Template testing with custom data
 * - Template cache management
 * - Email functionality validation
 * 
 * Security:
 * - Requires JWT authentication
 * - Accessible only to authenticated users
 * - Template testing for development purposes
 * 
 * Endpoints:
 * - GET /email/templates - List available templates
 * - POST /email/test - Test email template
 * - POST /email/clear-cache - Clear template cache
 * 
 * Usage:
 * - Development and testing of email templates
 * - Template cache management
 * - Email functionality validation
 */
@Controller('email')
  @UseGuards(CookieAuthGuard)
export class EmailController {
  constructor(
    private readonly mailService: MailService,
    private readonly templateService: TemplateService
  ) {}

  /**
   * Get available email templates
   * 
   * Retrieves a list of all available email templates in the system.
   * Useful for frontend template selection and development purposes.
   * 
   * @returns Promise with array of template names
   * 
   * @example
   * GET /email/templates
   * Response: ["verification", "reset", "welcome"]
   */
  @Get('templates')
  async getAvailableTemplates(): Promise<ApiResponseDto<string[]>> {
    try {
      const templates = await this.mailService.getAvailableTemplates();
      return ApiResponseDto.success(templates, 'Available templates retrieved successfully');
    } catch (error) {
      return ApiResponseDto.error('Failed to retrieve templates', error);
    }
  }

  /**
   * Test email template
   * 
   * Sends a test email using the specified template and data.
   * Allows developers to test email templates with custom data.
   * 
   * Process:
   * 1. Validates template type and data
   * 2. Renders email template with provided data
   * 3. Sends test email to specified recipient
   * 4. Returns success confirmation
   * 
   * @param testEmailDto - Email testing data including recipient, template type, and data
   * @returns Promise with test email confirmation
   * 
   * @example
   * POST /email/test
   * {
   *   "to": "test@example.com",
   *   "templateType": "verification",
   *   "data": {
   *     "userName": "John Doe",
   *     "verificationCode": "123456"
   *   }
   * }
   */
  @Post('test')
  @HttpCode(HttpStatus.OK)
  async testEmail(@Body() testEmailDto: TestEmailDto): Promise<ApiResponseDto<null>> {
    try {
      await this.mailService.sendEmail({
        to: testEmailDto.to,
        templateType: testEmailDto.templateType,
        data: testEmailDto.data
      });

      return ApiResponseDto.success(null, 'Test email sent successfully');
    } catch (error) {
      return ApiResponseDto.error('Failed to send test email', error);
    }
  }

  /**
   * Clear template cache
   * 
   * Clears the email template cache to force reload of templates.
   * Useful when templates are updated and need to be refreshed.
   * 
   * Process:
   * 1. Clears cached template data
   * 2. Forces template reload on next request
   * 3. Returns cache clearing confirmation
   * 
   * @returns Promise with cache clearing confirmation
   * 
   * @example
   * POST /email/clear-cache
   * Response: "Template cache cleared successfully"
   */
  @Post('clear-cache')
  @HttpCode(HttpStatus.OK)
  async clearCache(): Promise<ApiResponseDto<null>> {
    try {
      this.mailService.clearTemplateCache();
      return ApiResponseDto.success(null, 'Template cache cleared successfully');
    } catch (error) {
      return ApiResponseDto.error('Failed to clear cache', error);
    }
  }
} 