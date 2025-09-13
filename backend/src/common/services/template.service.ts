import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Interface for email template data
 * 
 * Defines the structure of data that can be injected into email templates.
 * Supports string, number, and boolean values for template variables.
 */
export interface EmailTemplateData {
  [key: string]: string | number | boolean;
}

/**
 * Available email template types
 * 
 * Defines the supported email template types for the application.
 * Each type corresponds to a specific email template file.
 */
export type EmailTemplateType = 'verification' | 'reset';

/**
 * Template Service
 * 
 * Manages email template loading, caching, and variable replacement.
 * Provides a centralized service for handling HTML email templates.
 * 
 * Features:
 * - Template caching for performance
 * - Variable replacement with data injection
 * - Support for multiple template types
 * - Automatic template discovery
 * - Error handling and logging
 * 
 * Template System:
 * - Templates stored as HTML files in 'src/common/templates/'
 * - Variable replacement using {{variableName}} syntax
 * - Automatic caching to improve performance
 * - Support for verification and reset email templates
 * 
 * Usage:
 * - Injected into services that need to send emails
 * - Provides processed HTML templates with injected data
 * - Supports template management and cache control
 * 
 * @example
 * // Get verification email template
 * const html = await this.templateService.getEmailTemplate('verification', {
 *   username: 'John Doe',
 *   verificationLink: 'https://example.com/verify?token=abc123'
 * });
 * 
 * @example
 * // Get reset password template
 * const html = await this.templateService.getEmailTemplate('reset', {
 *   username: 'John Doe',
 *   resetLink: 'https://example.com/reset?token=xyz789'
 * });
 */
@Injectable()
export class TemplateService {
  private readonly logger = new Logger(TemplateService.name);
  private readonly templateCache = new Map<string, string>();

  // ============================================================================
  // PRIVATE UTILITY METHODS
  // ============================================================================

  /**
   * Get templates directory path
   * 
   * Returns the absolute path to the templates directory.
   * Handles both development and Docker environments.
   * 
   * @returns Path to templates directory
   */
  private getTemplatesPath(): string {
    // In Docker, use absolute path to src directory
    return path.join(process.cwd(), 'src', 'common', 'templates');
  }

  /**
   * Load and cache a template
   * 
   * Loads a template file from disk and caches it for future use.
   * Implements caching to improve performance for frequently used templates.
   * 
   * @param templateName - Name of the template file (without extension)
   * @returns Promise with template content
   * @throws Error if template file is not found
   */
  private async loadTemplate(templateName: string): Promise<string> {
    // Check cache first for performance
    if (this.templateCache.has(templateName)) {
      return this.templateCache.get(templateName)!;
    }

    try {
      const templatesPath = this.getTemplatesPath();
      const templatePath = path.join(templatesPath, `${templateName}.template.html`);
      
  
      
      const templateContent = await fs.readFile(templatePath, 'utf-8');
      
      // Cache the template for future use
      this.templateCache.set(templateName, templateContent);
      
  
      return templateContent;
    } catch (error) {
      this.logger.error(`Failed to load template: ${templateName}`, error);
      throw new Error(`Template not found: ${templateName}`);
    }
  }

  /**
   * Replace variables in template with provided data
   * 
   * Processes a template by replacing {{variableName}} placeholders
   * with actual values from the provided data object.
   * 
   * @param template - Raw template content
   * @param data - Data object containing values to inject
   * @returns Processed template with replaced variables
   * 
   * @example
   * // Template: "Hello {{username}}, click {{link}}"
   * // Data: { username: "John", link: "https://example.com" }
   * // Result: "Hello John, click https://example.com"
   */
  private replaceVariables(template: string, data: EmailTemplateData): string {
    let processedTemplate = template;
    
    // Replace all variables in format {{variableName}}
    for (const [key, value] of Object.entries(data)) {
      const placeholder = new RegExp(`{{${key}}}`, 'g');
      processedTemplate = processedTemplate.replace(placeholder, String(value));
    }
    
    return processedTemplate;
  }

  // ============================================================================
  // PUBLIC TEMPLATE METHODS
  // ============================================================================

  /**
   * Get processed email template
   * 
   * Loads a template, replaces variables with provided data,
   * and returns the final HTML content ready for email sending.
   * 
   * @param templateType - Type of email template to load
   * @param data - Data to inject into template variables
   * @returns Promise with processed HTML template
   * @throws Error if template loading or processing fails
   * 
   * @example
   * const html = await this.getEmailTemplate('verification', {
   *   username: 'John Doe',
   *   verificationLink: 'https://example.com/verify?token=abc123',
   *   expiryTime: '24 hours'
   * });
   */
  async getEmailTemplate(templateType: EmailTemplateType, data: EmailTemplateData): Promise<string> {
    try {
      const template = await this.loadTemplate(templateType);
      const processedTemplate = this.replaceVariables(template, data);
      
  
      return processedTemplate;
    } catch (error) {
      this.logger.error(`Failed to process template: ${templateType}`, error);
      throw error;
    }
  }

  /**
   * Clear template cache
   * 
   * Removes all cached templates from memory.
   * Useful for development or when templates are updated.
   * 
   * @example
   * // Clear cache after template updates
   * this.templateService.clearCache();
   */
  clearCache(): void {
    this.templateCache.clear();

  }

  /**
   * Get available template types
   * 
   * Scans the templates directory and returns a list of
   * available template names (without file extensions).
   * 
   * @returns Promise with array of available template names
   * 
   * @example
   * const templates = await this.getAvailableTemplates();
   * // Returns: ['verification', 'reset']
   */
  async getAvailableTemplates(): Promise<string[]> {
    try {
      const templatesPath = this.getTemplatesPath();
      const files = await fs.readdir(templatesPath);
      return files
        .filter(file => file.endsWith('.template.html'))
        .map(file => file.replace('.template.html', ''));
    } catch (error) {
      this.logger.error('Failed to get available templates', error);
      return [];
    }
  }
} 