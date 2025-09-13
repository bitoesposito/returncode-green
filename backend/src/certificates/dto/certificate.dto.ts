import { 
  IsUUID, 
  IsString, 
  IsNotEmpty, 
  MaxLength, 
  IsOptional, 
  IsDateString,
  IsObject,
  MinLength
} from 'class-validator';

/**
 * Certificate Module DTOs (Data Transfer Objects)
 * 
 * This file contains all the validation DTOs used by the certificates module.
 * Each DTO includes comprehensive validation rules using class-validator
 * decorators to ensure data integrity and security.
 */

// ============================================================================
// CERTIFICATE GENERATION DTOs
// ============================================================================

/**
 * Data Transfer Object for certificate generation
 * 
 * Validates certificate generation request data with comprehensive
 * security checks and business rule validation.
 * 
 * Validation Rules:
 * - User UUID must be valid UUID format
 * - Course name must be provided and not exceed 255 characters
 * - Description is optional but limited to reasonable length
 * - Issue date is optional and defaults to current date
 * - Metadata is optional JSON object
 */
export class GenerateCertificateDto {
  /**
   * User UUID for certificate recipient
   * Must be a valid UUID format referencing existing user
   */
  @IsUUID(4, { message: 'User UUID must be a valid UUID v4' })
  @IsNotEmpty({ message: 'User UUID is required' })
  user_uuid: string;

  /**
   * Course name for the certificate
   * Must be provided and not exceed database field limits
   */
  @IsString()
  @IsNotEmpty({ message: 'Course name is required' })
  @MinLength(3, { message: 'Course name must be at least 3 characters' })
  @MaxLength(255, { message: 'Course name cannot exceed 255 characters' })
  course_name: string;

  /**
   * Optional description or additional certificate details
   * Limited to reasonable length for database storage
   */
  @IsString()
  @IsOptional()
  @MaxLength(1000, { message: 'Description cannot exceed 1000 characters' })
  description?: string;

  /**
   * Optional certificate issue date
   * Defaults to current date if not provided
   */
  @IsDateString({}, { message: 'Issue date must be a valid ISO date string' })
  @IsOptional()
  issued_date?: string;

  /**
   * Optional metadata for additional certificate information
   * Must be a valid JSON object if provided
   */
  @IsObject()
  @IsOptional()
  metadata?: Record<string, any>;
}

// ============================================================================
// CERTIFICATE RESPONSE DTOs
// ============================================================================

/**
 * Data Transfer Object for certificate response
 * 
 * Defines the structure of certificate data returned by API endpoints.
 * Contains all public certificate information safe for client consumption.
 */
export class CertificateResponseDto {
  /**
   * Unique certificate identifier
   */
  id: string;

  /**
   * Certificate owner's UUID
   */
  user_uuid: string;

  /**
   * Certificate owner's email (for identification)
   */
  user_email: string;

  /**
   * Course name for the certificate
   */
  course_name: string;

  /**
   * Certificate description
   */
  description: string | null;

  /**
   * Date when certificate was issued
   */
  issued_date: Date;

  /**
   * File path in storage (for authorized users)
   */
  file_path?: string;

  /**
   * Original filename
   */
  original_filename: string;

  /**
   * File content type
   */
  content_type: string;

  /**
   * File size in bytes
   */
  file_size: number;

  /**
   * Public key identifier used for signing
   */
  public_key_id: string;

  /**
   * Certificate revocation status
   */
  revoked: boolean;

  /**
   * Revocation timestamp if applicable
   */
  revoked_at: Date | null;

  /**
   * Revocation reason if applicable
   */
  revoked_reason: string | null;

  /**
   * Additional certificate metadata
   */
  metadata: Record<string, any>;

  /**
   * Certificate creation timestamp
   */
  created_at: Date;

  /**
   * Certificate last update timestamp
   */
  updated_at: Date;
}

// ============================================================================
// CERTIFICATE VERIFICATION DTOs
// ============================================================================

/**
 * Data Transfer Object for certificate verification result
 * 
 * Contains the complete result of certificate verification
 * including validity status and certificate information.
 */
export class VerificationResultDto {
  /**
   * Whether the certificate is valid
   */
  valid: boolean;

  /**
   * Certificate information if valid
   */
  certificate?: CertificateInfoDto;

  /**
   * Reason for invalidity if verification fails
   */
  reason?: string;

  /**
   * Timestamp when verification was performed
   */
  verified_at: Date;

  /**
   * Public key ID used for verification
   */
  public_key_id?: string;
}

/**
 * Data Transfer Object for public certificate information
 * 
 * Contains certificate information that can be safely shared
 * during verification without exposing sensitive data.
 */
export class CertificateInfoDto {
  /**
   * Certificate unique identifier
   */
  id: string;

  /**
   * Certificate owner's email (for identification)
   */
  user_email: string;

  /**
   * Course name
   */
  course_name: string;

  /**
   * Certificate description
   */
  description: string | null;

  /**
   * Issue date
   */
  issued_date: Date;

  /**
   * Whether certificate is revoked
   */
  revoked: boolean;

  /**
   * Public key identifier
   */
  public_key_id: string;

  /**
   * Additional metadata (filtered for public consumption)
   */
  metadata: Record<string, any>;
}

// ============================================================================
// CERTIFICATE REVOCATION DTOs
// ============================================================================

/**
 * Data Transfer Object for certificate revocation
 * 
 * Validates certificate revocation request with required reason
 * and optional additional details.
 */
export class RevokeCertificateDto {
  /**
   * Reason for certificate revocation
   * Must be provided for audit trail and transparency
   */
  @IsString()
  @IsNotEmpty({ message: 'Revocation reason is required' })
  @MinLength(10, { message: 'Revocation reason must be at least 10 characters' })
  @MaxLength(500, { message: 'Revocation reason cannot exceed 500 characters' })
  reason: string;

  /**
   * Optional additional details about the revocation
   */
  @IsString()
  @IsOptional()
  @MaxLength(1000, { message: 'Additional details cannot exceed 1000 characters' })
  additional_details?: string;
}

// ============================================================================
// CERTIFICATE LISTING DTOs
// ============================================================================

/**
 * Data Transfer Object for certificate listing query parameters
 * 
 * Validates query parameters for certificate listing endpoints
 * including pagination and filtering options.
 */
export class CertificateListQueryDto {
  /**
   * Page number for pagination (1-based)
   */
  @IsOptional()
  @IsString()
  page?: string;

  /**
   * Number of items per page
   */
  @IsOptional()
  @IsString()
  limit?: string;

  /**
   * Filter by course name (partial match)
   */
  @IsOptional()
  @IsString()
  @MaxLength(255, { message: 'Course name filter cannot exceed 255 characters' })
  course_name?: string;

  /**
   * Filter by revocation status
   */
  @IsOptional()
  @IsString()
  revoked?: string;

  /**
   * Sort field
   */
  @IsOptional()
  @IsString()
  sort_by?: string;

  /**
   * Sort order (asc or desc)
   */
  @IsOptional()
  @IsString()
  sort_order?: string;
}

/**
 * Data Transfer Object for paginated certificate list response
 * 
 * Contains paginated list of certificates with metadata
 * for client-side pagination handling.
 */
export class CertificateListResponseDto {
  /**
   * Array of certificates
   */
  certificates: CertificateResponseDto[];

  /**
   * Total number of certificates (before pagination)
   */
  total: number;

  /**
   * Current page number
   */
  page: number;

  /**
   * Number of items per page
   */
  limit: number;

  /**
   * Total number of pages
   */
  total_pages: number;

  /**
   * Whether there are more pages
   */
  has_next: boolean;

  /**
   * Whether there are previous pages
   */
  has_prev: boolean;
}