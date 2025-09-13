/**
 * Certificate Module Interfaces and Types
 * 
 * This file contains all the interfaces, enums, and types used by the certificates module.
 * Includes certificate data structures, verification results, and cryptographic configurations.
 */

// ============================================================================
// CERTIFICATE DATA INTERFACES
// ============================================================================

/**
 * Interface for certificate generation request data
 * 
 * Defines the structure of data required to generate a new certificate.
 * Used internally by the service layer for certificate creation.
 */
export interface CertificateGenerationData {
  /** User UUID from existing User entity */
  user_uuid: string;
  /** Course name for the certificate */
  course_name: string;
  /** Optional description or additional details */
  description?: string;
  /** Certificate file buffer */
  file_buffer: Buffer;
  /** Original filename */
  filename: string;
  /** File MIME type */
  mimetype: string;
}

/**
 * Interface for certificate metadata stored in database
 * 
 * Represents the complete certificate record structure
 * as stored in the PostgreSQL database.
 */
export interface CertificateMetadata {
  /** Unique certificate identifier */
  id: string;
  /** Associated user UUID */
  user_uuid: string;
  /** File path in MinIO storage */
  file_path: string;
  /** SHA256 hash of certificate content */
  hash: string;
  /** Digital signature (Base64 encoded) */
  signature: string;
  /** Public key identifier used for signing */
  public_key_id: string;
  /** Course name */
  course_name: string;
  /** Certificate issue date */
  issued_date: Date;
  /** Revocation status */
  revoked: boolean;
  /** Revocation timestamp */
  revoked_at: Date | null;
  /** Reason for revocation */
  revoked_reason: string | null;
  /** Creation timestamp */
  created_at: Date;
  /** Last update timestamp */
  updated_at: Date;
}

// ============================================================================
// VERIFICATION INTERFACES
// ============================================================================

/**
 * Interface for certificate verification result
 * 
 * Contains the complete result of certificate verification
 * including validity status and detailed information.
 */
export interface VerificationResult {
  /** Whether the certificate is valid */
  valid: boolean;
  /** Certificate metadata if valid */
  certificate?: CertificateInfo;
  /** Reason for invalidity if verification fails */
  reason?: string;
  /** Timestamp when verification was performed */
  verified_at: Date;
  /** Public key ID used for verification */
  public_key_id?: string;
}

/**
 * Interface for certificate information returned in verification
 * 
 * Contains public certificate information that can be safely
 * shared during verification without exposing sensitive data.
 */
export interface CertificateInfo {
  /** Certificate unique identifier */
  id: string;
  /** User email (for identification) */
  user_email: string;
  /** Course name */
  course_name: string;
  /** Issue date */
  issued_date: Date;
  /** Whether certificate is revoked */
  revoked: boolean;
  /** Public key identifier */
  public_key_id: string;
}

// ============================================================================
// CRYPTOGRAPHIC INTERFACES
// ============================================================================

/**
 * Interface for cryptographic key information
 * 
 * Represents a cryptographic key pair with metadata
 * for certificate signing and verification operations.
 */
export interface CryptographicKey {
  /** Unique key identifier */
  key_id: string;
  /** Key algorithm (RSA or ECDSA) */
  algorithm: KeyAlgorithm;
  /** Key size in bits */
  key_size: number;
  /** Public key in PEM format */
  public_key: string;
  /** Private key in PEM format (only for signing) */
  private_key?: string;
  /** Key creation date */
  created_at: Date;
  /** Key expiration date */
  expires_at?: Date;
  /** Whether key is active */
  active: boolean;
}

/**
 * Enum for supported cryptographic algorithms
 * 
 * Defines the cryptographic algorithms supported
 * for certificate signing and verification.
 */
export enum KeyAlgorithm {
  /** RSA with PKCS#1 v1.5 padding */
  RSA = 'RSA',
  /** Elliptic Curve Digital Signature Algorithm */
  ECDSA = 'ECDSA',
}

/**
 * Interface for signature generation parameters
 * 
 * Contains parameters required for generating
 * digital signatures for certificates.
 */
export interface SignatureParams {
  /** Data hash to be signed */
  hash: string;
  /** Private key for signing */
  private_key: string;
  /** Algorithm to use for signing */
  algorithm: KeyAlgorithm;
  /** Key identifier */
  key_id: string;
}

/**
 * Interface for signature verification parameters
 * 
 * Contains parameters required for verifying
 * digital signatures of certificates.
 */
export interface VerificationParams {
  /** Original data hash */
  hash: string;
  /** Signature to verify */
  signature: string;
  /** Public key for verification */
  public_key: string;
  /** Algorithm used for signing */
  algorithm: KeyAlgorithm;
}

// ============================================================================
// FILE STORAGE INTERFACES
// ============================================================================

/**
 * Interface for certificate file storage information
 * 
 * Contains information about certificate file storage
 * in MinIO object storage system.
 */
export interface CertificateFileInfo {
  /** File path in MinIO bucket */
  file_path: string;
  /** File size in bytes */
  file_size: number;
  /** File MIME type */
  content_type: string;
  /** File upload timestamp */
  uploaded_at: Date;
  /** Public URL for file access */
  public_url: string;
}

/**
 * Interface for file upload result
 * 
 * Contains the result of certificate file upload
 * to MinIO storage system.
 */
export interface FileUploadResult {
  /** Success status */
  success: boolean;
  /** File path if successful */
  file_path?: string;
  /** Public URL if successful */
  public_url?: string;
  /** Error message if failed */
  error?: string;
}

// ============================================================================
// AUDIT AND LOGGING INTERFACES
// ============================================================================

/**
 * Interface for certificate audit event data
 * 
 * Contains structured data for certificate-related
 * audit events and security logging.
 */
export interface CertificateAuditEvent {
  /** Event type identifier */
  event_type: CertificateEventType;
  /** Certificate ID involved */
  certificate_id: string;
  /** User ID performing the action */
  user_id?: string;
  /** Additional event details */
  details: Record<string, any>;
  /** Client IP address */
  ip_address?: string;
  /** User agent string */
  user_agent?: string;
}

/**
 * Enum for certificate-related audit event types
 * 
 * Defines the types of events that should be logged
 * for certificate operations and security monitoring.
 */
export enum CertificateEventType {
  /** Certificate generation event */
  CERTIFICATE_GENERATED = 'CERTIFICATE_GENERATED',
  /** Certificate verification event */
  CERTIFICATE_VERIFIED = 'CERTIFICATE_VERIFIED',
  /** Certificate download event */
  CERTIFICATE_DOWNLOADED = 'CERTIFICATE_DOWNLOADED',
  /** Certificate revocation event */
  CERTIFICATE_REVOKED = 'CERTIFICATE_REVOKED',
  /** Failed verification attempt */
  VERIFICATION_FAILED = 'VERIFICATION_FAILED',
  /** Unauthorized access attempt */
  UNAUTHORIZED_ACCESS = 'UNAUTHORIZED_ACCESS',
  /** Key usage event */
  KEY_USED = 'KEY_USED',
}

// ============================================================================
// ERROR INTERFACES
// ============================================================================

/**
 * Interface for certificate-specific error information
 * 
 * Extends standard error information with certificate-specific
 * context and details for better error handling.
 */
export interface CertificateError {
  /** Error code identifier */
  code: CertificateErrorCode;
  /** Human-readable error message */
  message: string;
  /** Additional error details */
  details?: Record<string, any>;
  /** Certificate ID if applicable */
  certificate_id?: string;
  /** Timestamp when error occurred */
  timestamp: Date;
}

/**
 * Enum for certificate-specific error codes
 * 
 * Defines standardized error codes for certificate
 * operations to enable consistent error handling.
 */
export enum CertificateErrorCode {
  /** Certificate not found */
  CERTIFICATE_NOT_FOUND = 'CERTIFICATE_NOT_FOUND',
  /** Invalid certificate format */
  INVALID_CERTIFICATE = 'INVALID_CERTIFICATE',
  /** Signature verification failed */
  SIGNATURE_VERIFICATION_FAILED = 'SIGNATURE_VERIFICATION_FAILED',
  /** Certificate has been revoked */
  CERTIFICATE_REVOKED = 'CERTIFICATE_REVOKED',
  /** Cryptographic key not found */
  KEY_NOT_FOUND = 'KEY_NOT_FOUND',
  /** File storage error */
  STORAGE_ERROR = 'STORAGE_ERROR',
  /** Hash calculation error */
  HASH_CALCULATION_ERROR = 'HASH_CALCULATION_ERROR',
  /** Unauthorized access to certificate */
  UNAUTHORIZED_ACCESS = 'UNAUTHORIZED_ACCESS',
  /** Invalid file format */
  INVALID_FILE_FORMAT = 'INVALID_FILE_FORMAT',
  /** File size exceeded */
  FILE_SIZE_EXCEEDED = 'FILE_SIZE_EXCEEDED',
}