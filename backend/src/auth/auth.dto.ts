import { 
  IsEmail, 
  IsString, 
  MinLength, 
  MaxLength, 
  Matches, 
  IsNotEmpty, 
  IsOptional, 
  Length, 
  IsBoolean 
} from 'class-validator';

// Local imports
import { VALIDATION_PATTERNS } from '../common/common.interface';

/**
 * Auth Module DTOs (Data Transfer Objects)
 * 
 * This file contains all the validation DTOs used by the auth module.
 * Each DTO includes comprehensive validation rules using class-validator
 * decorators to ensure data integrity and security.
 */

// ============================================================================
// AUTHENTICATION DTOs
// ============================================================================

/**
 * Data Transfer Object for user login
 * 
 * Validates login credentials with comprehensive security checks.
 * Includes optional "remember me" functionality for extended sessions.
 * 
 * Validation Rules:
 * - Email must be valid format and not empty
 * - Password must meet security requirements
 * - Remember me is optional boolean flag
 */
export class LoginDto {
  /**
   * User's email address
   * Must be a valid email format and not exceed 255 characters
   */
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  @MaxLength(255, { message: 'Email cannot exceed 255 characters' })
  email: string;

  /**
   * User's password
   * Must meet security requirements including length and complexity
   */
  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @MaxLength(128, { message: 'Password cannot exceed 128 characters' })
  @Matches(VALIDATION_PATTERNS.PASSWORD, {
    message: 'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character'
  })
  password: string;

  /**
   * Remember me flag for extended sessions
   * Optional boolean that affects token expiration times
   */
  @IsBoolean()
  @IsOptional()
  rememberMe?: boolean;
}

/**
 * Data Transfer Object for user registration
 * 
 * Validates new user registration data with security requirements.
 * Ensures strong password policy and valid email format.
 * 
 * Validation Rules:
 * - Email must be valid format and not empty
 * - Password must meet security requirements
 * - No duplicate email validation (handled in service)
 */
export class RegisterDto {
  /**
   * User's email address for registration
   * Must be a valid email format and not exceed 255 characters
   */
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  @MaxLength(255, { message: 'Email cannot exceed 255 characters' })
  email: string;

  /**
   * User's password for registration
   * Must meet security requirements including length and complexity
   */
  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @MaxLength(128, { message: 'Password cannot exceed 128 characters' })
  @Matches(VALIDATION_PATTERNS.PASSWORD, {
    message: 'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character'
  })
  password: string;
}

// ============================================================================
// TOKEN MANAGEMENT DTOs
// ============================================================================

/**
 * Data Transfer Object for refresh token requests
 * 
 * Validates refresh token for JWT token renewal.
 * Ensures token is provided and is a valid string.
 * 
 * Validation Rules:
 * - Refresh token must be a non-empty string
 */
export class RefreshTokenDto {
  /**
   * Refresh token for generating new access token
   * Must be a valid JWT refresh token string
   */
  @IsString()
  @IsNotEmpty({ message: 'Refresh token is required' })
  refresh_token: string;
}

// ============================================================================
// PASSWORD RECOVERY DTOs
// ============================================================================

/**
 * Data Transfer Object for forgot password requests
 * 
 * Validates email address for password reset initiation.
 * Used to send password reset OTP to user's email.
 * 
 * Validation Rules:
 * - Email must be valid format and not empty
 */
export class ForgotPasswordDto {
  /**
   * User's email address for password reset
   * Must be a valid email format for sending reset OTP
   */
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;
}

/**
 * Data Transfer Object for password reset
 * 
 * Validates OTP and new password for password reset completion.
 * Ensures strong password policy for new password.
 * 
 * Validation Rules:
 * - OTP must be exactly 6 characters
 * - New password must meet security requirements
 */
export class ResetPasswordDto {
  /**
   * One-time password (OTP) for password reset
   * Must be exactly 6 characters (numeric code)
   */
  @IsString()
  @IsNotEmpty({ message: 'OTP is required' })
  @Length(6, 6, { message: 'OTP must be exactly 6 characters' })
  otp: string;

  /**
   * New password for account
   * Must meet security requirements including length and complexity
   */
  @IsString()
  @IsNotEmpty({ message: 'New password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @MaxLength(128, { message: 'Password cannot exceed 128 characters' })
  @Matches(VALIDATION_PATTERNS.PASSWORD, {
    message: 'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character'
  })
  password: string;
}

// ============================================================================
// EMAIL VERIFICATION DTOs
// ============================================================================

/**
 * Data Transfer Object for email verification
 * 
 * Validates verification token for email verification process.
 * Ensures token is provided for verification.
 * 
 * Validation Rules:
 * - Verification token must be a non-empty string
 */
export class VerifyEmailDto {
  /**
   * Email verification token
   * Must be a valid verification token string
   */
  @IsString()
  @IsNotEmpty({ message: 'Verification token is required' })
  token: string;
}

/**
 * Data Transfer Object for resending verification email
 * 
 * Validates email address for verification email resend.
 * Used when original verification email expires or is lost.
 * 
 * Validation Rules:
 * - Email must be valid format and not empty
 */
export class ResendVerificationDto {
  /**
   * User's email address for verification resend
   * Must be a valid email format for sending verification email
   */
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;
}