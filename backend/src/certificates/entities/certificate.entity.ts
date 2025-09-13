import { 
  Entity, 
  Column, 
  PrimaryGeneratedColumn, 
  CreateDateColumn, 
  UpdateDateColumn, 
  ManyToOne, 
  JoinColumn 
} from 'typeorm';

// Local imports
import { User } from '../../auth/entities/user.entity';

/**
 * Certificate Entity
 * 
 * Represents a digital certificate in the database. This entity stores
 * certificate metadata including cryptographic signatures, file references,
 * and revocation status for post-course certification system.
 * 
 * Features:
 * - UUID primary key for unique identification
 * - Relationship with User entity for certificate ownership
 * - Cryptographic hash and signature storage
 * - File path reference to MinIO storage
 * - Revocation support with audit trail
 * - Automatic timestamp tracking (created_at, updated_at)
 * 
 * Database:
 * - Table name: 'certificates'
 * - Uses PostgreSQL-specific features (UUID, timestamp with timezone)
 * - Foreign key relationship with auth_users table
 * - Indexes on user_uuid and public_key_id for performance
 * 
 * Security:
 * - Stores SHA256 hash for file integrity verification
 * - Digital signature (Base64 encoded) for authenticity
 * - Public key identifier for signature verification
 * - Revocation status and audit trail
 * 
 * Usage:
 * - Created when certificates are generated for users
 * - Updated when certificates are revoked
 * - Queried for verification and user certificate listings
 * - Accessed via User entity relationship
 * 
 * @example
 * // Create new certificate
 * const certificate = new Certificate();
 * certificate.user_uuid = 'user-uuid';
 * certificate.course_name = 'Advanced TypeScript';
 * certificate.hash = 'sha256-hash';
 * certificate.signature = 'base64-signature';
 * 
 * @example
 * // Query with user relationship
 * const certificate = await certificateRepository.findOne({ 
 *   where: { id: certificateId }, 
 *   relations: ['user'] 
 * });
 */
@Entity('certificates')
export class Certificate {
  // ============================================================================
  // PRIMARY KEY
  // ============================================================================

  /**
   * Unique identifier for the certificate
   * 
   * Auto-generated UUID primary key that uniquely identifies
   * each certificate in the system.
   * 
   * @example "123e4567-e89b-12d3-a456-426614174000"
   */
  @PrimaryGeneratedColumn('uuid')
  id: string;

  // ============================================================================
  // USER RELATIONSHIP FIELDS
  // ============================================================================

  /**
   * Foreign key reference to the certificate owner
   * 
   * Links the certificate to the user who earned it.
   * Used for authorization and certificate ownership validation.
   * 
   * @example "user-uuid-123"
   */
  @Column({ name: 'user_uuid', type: 'uuid' })
  user_uuid: string;

  // ============================================================================
  // CERTIFICATE CONTENT FIELDS
  // ============================================================================

  /**
   * Course name for which the certificate was issued
   * 
   * Human-readable course name that appears on the certificate.
   * Used for display purposes and certificate identification.
   * 
   * @example "Advanced TypeScript Development"
   */
  @Column({ name: 'course_name', type: 'varchar', length: 255 })
  course_name: string;

  /**
   * Optional description or additional certificate details
   * 
   * Additional information about the certificate, course completion
   * requirements, or other relevant details.
   * 
   * @example "Comprehensive course covering advanced TypeScript concepts, design patterns, and best practices"
   */
  @Column({ name: 'description', type: 'text', nullable: true })
  description: string | null;

  /**
   * Date when the certificate was issued
   * 
   * Timestamp indicating when the certificate was officially issued.
   * May differ from created_at if there's a delay in processing.
   * 
   * @example "2024-01-15T10:30:00.000Z"
   */
  @Column({ name: 'issued_date', type: 'timestamp' })
  issued_date: Date;

  // ============================================================================
  // FILE STORAGE FIELDS
  // ============================================================================

  /**
   * File path in MinIO object storage
   * 
   * Complete path to the certificate file stored in MinIO bucket.
   * Used for file retrieval and download operations.
   * 
   * @example "certificates/2024/01/user-uuid/certificate-id.pdf"
   */
  @Column({ name: 'file_path', type: 'varchar', length: 500 })
  file_path: string;

  /**
   * Original filename of the uploaded certificate
   * 
   * Preserves the original filename for download operations
   * and user-friendly file naming.
   * 
   * @example "typescript-advanced-certificate.pdf"
   */
  @Column({ name: 'original_filename', type: 'varchar', length: 255 })
  original_filename: string;

  /**
   * MIME type of the certificate file
   * 
   * Content type of the stored file for proper HTTP headers
   * and file handling during downloads.
   * 
   * @example "application/pdf"
   */
  @Column({ name: 'content_type', type: 'varchar', length: 100 })
  content_type: string;

  /**
   * File size in bytes
   * 
   * Size of the certificate file for storage management
   * and download progress indication.
   * 
   * @example 1048576
   */
  @Column({ name: 'file_size', type: 'bigint' })
  file_size: number;

  // ============================================================================
  // CRYPTOGRAPHIC FIELDS
  // ============================================================================

  /**
   * SHA256 hash of the certificate file content
   * 
   * Cryptographic hash used for file integrity verification
   * and digital signature generation. Calculated from file buffer.
   * 
   * @example "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
   */
  @Column({ name: 'hash', type: 'varchar', length: 64 })
  hash: string;

  /**
   * Digital signature of the certificate hash
   * 
   * Base64-encoded digital signature generated using RSA/ECDSA
   * private key. Used for certificate authenticity verification.
   * 
   * @example "MEUCIQDx1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9..."
   */
  @Column({ name: 'signature', type: 'text' })
  signature: string;

  /**
   * Public key identifier used for signature generation
   * 
   * Identifier of the cryptographic key pair used to sign
   * the certificate. Enables key rotation and verification.
   * 
   * @example "rsa-2024-01"
   */
  @Column({ name: 'public_key_id', type: 'varchar', length: 100 })
  public_key_id: string;

  // ============================================================================
  // REVOCATION FIELDS
  // ============================================================================

  /**
   * Certificate revocation status
   * 
   * Boolean flag indicating whether the certificate has been revoked.
   * Revoked certificates fail verification regardless of signature validity.
   * 
   * @example false
   */
  @Column({ name: 'revoked', type: 'boolean', default: false })
  revoked: boolean;

  /**
   * Timestamp when the certificate was revoked
   * 
   * Date and time when the certificate was marked as revoked.
   * Null if the certificate has not been revoked.
   * 
   * @example "2024-02-15T14:30:00.000Z"
   */
  @Column({ name: 'revoked_at', type: 'timestamp', nullable: true })
  revoked_at: Date | null;

  /**
   * Reason for certificate revocation
   * 
   * Human-readable explanation for why the certificate was revoked.
   * Used for audit trails and administrative purposes.
   * 
   * @example "Certificate issued in error - incorrect course completion date"
   */
  @Column({ name: 'revoked_reason', type: 'text', nullable: true })
  revoked_reason: string | null;

  /**
   * User ID who performed the revocation
   * 
   * UUID of the administrator who revoked the certificate.
   * Used for audit trails and accountability.
   * 
   * @example "admin-uuid-456"
   */
  @Column({ name: 'revoked_by', type: 'uuid', nullable: true })
  revoked_by: string | null;

  // ============================================================================
  // METADATA FIELDS
  // ============================================================================

  /**
   * Additional certificate metadata
   * 
   * JSONB field for storing flexible certificate metadata such as
   * course details, completion requirements, or custom attributes.
   * 
   * @example
   * {
   *   "course_duration": "40 hours",
   *   "completion_score": "95%",
   *   "instructor": "John Doe",
   *   "certificate_template": "advanced-template-v2"
   * }
   */
  @Column({ name: 'metadata', type: 'jsonb', default: {} })
  metadata: Record<string, any>;

  // ============================================================================
  // TIMESTAMP FIELDS
  // ============================================================================

  /**
   * Timestamp when the certificate record was created
   * 
   * Automatically set by TypeORM when the entity is first saved.
   * Used for audit trails and certificate age calculations.
   * 
   * @example "2024-01-15T10:30:00.000Z"
   */
  @CreateDateColumn({ name: 'created_at' })
  created_at: Date;

  /**
   * Timestamp when the certificate record was last updated
   * 
   * Automatically updated by TypeORM whenever the entity is saved.
   * Used for tracking certificate changes and cache invalidation.
   * 
   * @example "2024-01-15T11:45:00.000Z"
   */
  @UpdateDateColumn({ name: 'updated_at' })
  updated_at: Date;

  // ============================================================================
  // RELATIONSHIPS
  // ============================================================================

  /**
   * Many-to-one relationship with User entity
   * 
   * Each certificate belongs to exactly one user, but each user
   * can have multiple certificates. This relationship enables
   * certificate ownership validation and user certificate listings.
   * 
   * Access pattern:
   * - From Certificate: certificate.user (populated via relations)
   * - From User: user.certificates (reverse relationship)
   * 
   * @example
   * // Access user from certificate
   * const certificate = await certificateRepository.findOne({ 
   *   where: { id: certificateId }, 
   *   relations: ['user'] 
   * });
   * console.log(certificate.user.email); // "user@example.com"
   */
  @ManyToOne(() => User, { nullable: false })
  @JoinColumn({ name: 'user_uuid', referencedColumnName: 'uuid' })
  user: User;
}