import { IsString, IsOptional, Length, IsArray, IsObject } from 'class-validator';

/**
 * Update Profile Data Transfer Object
 * 
 * Defines the structure for user profile update requests with comprehensive
 * validation rules for tags and metadata fields. Ensures data integrity
 * and prevents malicious or excessive data submissions.
 * 
 * Validation Rules:
 * - Tags: Array of strings, max 20 tags, unique values, max 50 chars each
 * - Metadata: JSON object, max 10KB size, must be valid object
 * - Both fields are optional for partial updates
 * 
 * @example
 * // Update tags only
 * {
 *   "tags": ["developer", "typescript", "nestjs"]
 * }
 * 
 * @example
 * // Update metadata only
 * {
 *   "metadata": {
 *     "preferences": { "theme": "dark", "language": "en" },
 *     "bio": "Full-stack developer"
 *   }
 * }
 * 
 * @example
 * // Update both fields
 * {
 *   "tags": ["developer", "backend"],
 *   "metadata": {
 *     "location": "Italy",
 *     "skills": ["Node.js", "TypeScript"]
 *   }
 * }
 */
export class UpdateProfileDto {
  /**
   * User-defined tags for categorization and organization
   * 
   * Validation:
   * - Must be an array of strings
   * - Maximum 20 tags allowed
   * - Tags must be unique (no duplicates)
   * - Individual tags cannot exceed 50 characters
   * - Empty or whitespace-only tags are filtered out
   * 
   * @example ["developer", "backend", "typescript", "nestjs"]
   */
  @IsArray()
  @IsOptional()
  tags?: string[];

  /**
   * Flexible metadata storage for additional user data
   * 
   * Validation:
   * - Must be a valid JSON object
   * - Cannot be null
   * - Maximum size of 10KB when serialized
   * - Merged with existing metadata (not replaced)
   * 
   * Common use cases:
   * - User preferences and settings
   * - Profile information (bio, location, etc.)
   * - Application-specific data
   * - Custom user attributes
   * 
   * @example
   * {
   *   "preferences": { "theme": "dark", "notifications": true },
   *   "bio": "Passionate developer",
   *   "location": "Milan, Italy",
   *   "skills": ["JavaScript", "TypeScript", "Node.js"]
   * }
   */
  @IsObject()
  @IsOptional()
  metadata?: Record<string, any>;
} 