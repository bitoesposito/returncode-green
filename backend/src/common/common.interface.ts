/**
 * Common Interfaces and Utilities
 * 
 * Provides shared interfaces, DTOs, and validation patterns used across
 * the application for consistent API responses and data validation.
 * 
 * Features:
 * - Standardized API response structure
 * - Response builder utilities
 * - Common validation patterns
 * - Type-safe response handling
 * 
 * Usage:
 * - Imported by controllers for consistent API responses
 * - Used for DTO validation and transformation
 * - Provides reusable validation patterns
 * - Ensures API consistency across the application
 */

// ============================================================================
// API RESPONSE INTERFACES
// ============================================================================

/**
 * Standard API response interface
 * 
 * Defines the structure for all API responses to ensure consistency
 * across the application. Provides success/error status, messages,
 * and typed data payloads.
 * 
 * @template T - Type of the data payload
 * 
 * @example
 * // Success response
 * const response: ApiResponse<User> = {
 *   http_status_code: 200,
 *   success: true,
 *   message: 'User created successfully',
 *   data: { id: '123', email: 'user@example.com' }
 * };
 * 
 * @example
 * // Error response
 * const response: ApiResponse<null> = {
 *   http_status_code: 400,
 *   success: false,
 *   message: 'Invalid input data',
 *   data: null
 * };
 */
export interface ApiResponse<T> {
  /** HTTP status code for the response */
  http_status_code: number;
  /** Boolean indicating if the operation was successful */
  success: boolean;
  /** Human-readable message describing the result */
  message: string;
  /** Typed data payload (null for error responses) */
  data: T;
}

// ============================================================================
// API RESPONSE DTO CLASS
// ============================================================================

/**
 * API Response DTO with builder methods
 * 
 * Provides utility methods for creating standardized API responses.
 * Includes static methods for success and error responses with
 * appropriate default values.
 * 
 * Features:
 * - Static builder methods for common response types
 * - Automatic status code assignment
 * - Type-safe data handling
 * - Consistent error response structure
 * 
 * @template T - Type of the data payload
 * 
 * @example
 * // Create success response
 * const successResponse = ApiResponseDto.success(userData, 'User retrieved successfully');
 * 
 * @example
 * // Create error response
 * const errorResponse = ApiResponseDto.error('User not found', 404);
 * 
 * @example
 * // Use in controller
 * @Get(':id')
 * async getUser(@Param('id') id: string): Promise<ApiResponseDto<User>> {
 *   try {
 *     const user = await this.userService.findById(id);
 *     return ApiResponseDto.success(user, 'User found');
 *   } catch (error) {
 *     return ApiResponseDto.error('User not found', 404);
 *   }
 * }
 */
export class ApiResponseDto<T> {
  /** HTTP status code for the response */
  http_status_code: number;
  /** Boolean indicating if the operation was successful */
  success: boolean;
  /** Human-readable message describing the result */
  message: string;
  /** Typed data payload (null for error responses) */
  data: T;

  /**
   * Create a successful API response
   * 
   * Builds a standardized success response with HTTP 200 status code
   * and the provided data and message.
   * 
   * @param data - Data payload to include in the response
   * @param message - Success message (defaults to 'Success')
   * @returns ApiResponseDto with success structure
   * 
   * @example
   * const response = ApiResponseDto.success({ id: '123', name: 'John' }, 'User created');
   * // Returns: { http_status_code: 200, success: true, message: 'User created', data: {...} }
   */
  static success<T>(data: T, message: string = 'Success'): ApiResponseDto<T> {
    return {
      http_status_code: 200,
      success: true,
      message,
      data,
    };
  }

  /**
   * Create an error API response
   * 
   * Builds a standardized error response with the specified status code
   * and error message. Data is set to null for error responses.
   * 
   * @param message - Error message describing the issue
   * @param http_status_code - HTTP status code (defaults to 200, should be 4xx/5xx)
   * @returns ApiResponseDto with error structure
   * 
   * @example
   * const response = ApiResponseDto.error('Validation failed', 400);
   * // Returns: { http_status_code: 400, success: false, message: 'Validation failed', data: null }
   */
  static error<T>(message: string, http_status_code: number = 200): ApiResponseDto<T> {
    return {
      http_status_code,
      success: false,
      message,
      data: null as T,
    };
  }
}

// ============================================================================
// VALIDATION PATTERNS
// ============================================================================

/**
 * Common validation patterns
 * 
 * Provides pre-defined regular expressions for common validation scenarios.
 * These patterns ensure consistent validation across the application
 * and reduce code duplication.
 * 
 * Usage:
 * - Import and use in DTOs for field validation
 * - Apply in custom validators
 * - Use in form validation on frontend
 * - Ensure consistent validation rules
 * 
 * @example
 * // In a DTO class
 * @IsEmail()
 * @Matches(VALIDATION_PATTERNS.EMAIL)
 * email: string;
 * 
 * @example
 * // In a custom validator
 * if (!VALIDATION_PATTERNS.PASSWORD.test(password)) {
 *   throw new BadRequestException('Password does not meet requirements');
 * }
 */
export const VALIDATION_PATTERNS = {
  /**
   * Email validation pattern
   * 
   * Validates email addresses with standard format:
   * - Allows letters, numbers, dots, underscores, percent, plus, minus
   * - Requires @ symbol
   * - Domain must have valid TLD (2+ characters)
   * 
   * @example
   * VALIDATION_PATTERNS.EMAIL.test('user@example.com') // true
   * VALIDATION_PATTERNS.EMAIL.test('invalid-email') // false
   */
  EMAIL: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,

  /**
   * Phone number validation pattern
   * 
   * Validates phone numbers with exactly 10 digits:
   * - Only numeric characters allowed
   * - Must be exactly 10 digits
   * - No spaces, dashes, or other separators
   * 
   * @example
   * VALIDATION_PATTERNS.PHONE.test('1234567890') // true
   * VALIDATION_PATTERNS.PHONE.test('123-456-7890') // false
   */
  PHONE: /^[0-9]{10}$/,

  /**
   * Area code validation pattern
   * 
   * Validates international area codes:
   * - Must start with + symbol
   * - Followed by 1-4 digits
   * - Common format for country codes
   * 
   * @example
   * VALIDATION_PATTERNS.AREA_CODE.test('+1') // true
   * VALIDATION_PATTERNS.AREA_CODE.test('+1234') // true
   * VALIDATION_PATTERNS.AREA_CODE.test('1') // false
   */
  AREA_CODE: /^\+[0-9]{1,4}$/,

  /**
   * URL slug validation pattern
   * 
   * Validates URL-friendly slugs:
   * - Lowercase letters and numbers only
   * - Hyphens allowed as separators
   * - No consecutive hyphens
   * - No leading or trailing hyphens
   * 
   * @example
   * VALIDATION_PATTERNS.SLUG.test('my-article-title') // true
   * VALIDATION_PATTERNS.SLUG.test('My Article Title') // false
   * VALIDATION_PATTERNS.SLUG.test('my--article') // false
   */
  SLUG: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,

  /**
   * Website URL validation pattern
   * 
   * Validates website URLs:
   * - Supports http and https protocols
   * - Optional www subdomain
   * - Valid domain structure
   * - Allows query parameters and paths
   * 
   * @example
   * VALIDATION_PATTERNS.WEBSITE.test('https://example.com') // true
   * VALIDATION_PATTERNS.WEBSITE.test('http://www.example.com/path?param=value') // true
   * VALIDATION_PATTERNS.WEBSITE.test('not-a-url') // false
   */
  WEBSITE: /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/,

  /**
   * Strong password validation pattern
   * 
   * Validates strong passwords with the following requirements:
   * - At least 8 characters long
   * - Contains at least one lowercase letter
   * - Contains at least one uppercase letter
   * - Contains at least one digit
   * - Contains at least one special character
   * 
   * @example
   * VALIDATION_PATTERNS.PASSWORD.test('MyP@ssw0rd') // true
   * VALIDATION_PATTERNS.PASSWORD.test('password') // false (missing requirements)
   * VALIDATION_PATTERNS.PASSWORD.test('Password1') // false (missing special char)
   */
  PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/
}; 