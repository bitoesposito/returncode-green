import { 
  Entity, 
  Column, 
  PrimaryGeneratedColumn, 
  CreateDateColumn, 
  UpdateDateColumn, 
  OneToOne, 
  JoinColumn 
} from 'typeorm';

// Local imports
import { UserRole } from '../auth.interface';
import { UserProfile } from '../../users/entities/user-profile.entity';

/**
 * User Entity
 * 
 * Core user entity representing a system user account.
 * Maps to the 'auth_users' table in the database and contains
 * all authentication and authorization related user data.
 * 
 * Features:
 * - UUID-based primary key for security
 * - Email-based authentication
 * - Role-based access control
 * - Account verification system
 * - Password reset functionality
 * - Refresh token management
 * - Profile relationship
 * 
 * Security Considerations:
 * - Password stored as hash only
 * - Tokens have expiration dates
 * - Account can be deactivated
 * - Email verification required
 */
@Entity('auth_users')
export class User {
  // ============================================================================
  // PRIMARY KEY
  // ============================================================================

  /**
   * Unique identifier for the user
   * Auto-generated UUID for security and uniqueness
   */
  @PrimaryGeneratedColumn('uuid')
  uuid: string;

  // ============================================================================
  // AUTHENTICATION FIELDS
  // ============================================================================

  /**
   * User's email address
   * Used as the primary login identifier
   * Must be unique across the system
   */
  @Column({ unique: true, length: 255 })
  email: string;

  /**
   * Hashed password for user authentication
   * Never stored in plain text
   */
  @Column({ name: 'password_hash' })
  password_hash: string;

  // ============================================================================
  // AUTHORIZATION FIELDS
  // ============================================================================

  /**
   * User's role in the system
   * Determines access permissions and capabilities
   * Defaults to 'user' role
   */
  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.user
  })
  role: UserRole;

  // ============================================================================
  // ACCOUNT STATUS FIELDS
  // ============================================================================

  /**
   * Whether the user account is active
   * Inactive accounts cannot log in
   * Defaults to true for new accounts
   */
  @Column({ name: 'is_active', default: true })
  is_active: boolean;

  /**
   * Whether the user's email has been verified
   * Required for full account access
   * Defaults to false for new accounts
   */
  @Column({ name: 'is_verified', default: false })
  is_verified: boolean;

  /**
   * Whether the user has completed initial setup
   * Used to determine if profile setup is required
   * Defaults to false for new accounts
   */
  @Column({ name: 'is_configured', default: false })
  is_configured: boolean;

  // ============================================================================
  // EMAIL VERIFICATION FIELDS
  // ============================================================================

  /**
   * Token used for email verification
   * Generated when user registers or requests verification
   * Nullified after successful verification
   */
  @Column({ name: 'verification_token', nullable: true, type: 'text' })
  verification_token: string | null;

  /**
   * Expiration date for email verification token
   * Prevents use of stale verification tokens
   */
  @Column({ name: 'verification_expires', nullable: true, type: 'timestamp' })
  verification_expires: Date | null;

  // ============================================================================
  // PASSWORD RESET FIELDS
  // ============================================================================

  /**
   * Token used for password reset
   * Generated when user requests password reset
   * Nullified after successful password change
   */
  @Column({ name: 'reset_token', nullable: true, type: 'text' })
  reset_token: string | null;

  /**
   * Expiration date for password reset token
   * Prevents use of stale reset tokens
   */
  @Column({ name: 'reset_token_expiry', nullable: true, type: 'timestamp' })
  reset_token_expiry: Date | null;

  // ============================================================================
  // SESSION MANAGEMENT FIELDS
  // ============================================================================

  /**
   * Refresh token for maintaining user sessions
   * Used to obtain new access tokens
   * Nullified on logout or expiration
   */
  @Column({ name: 'refresh_token', nullable: true, type: 'text' })
  refresh_token: string | null;

  /**
   * Expiration date for refresh token
   * Forces re-authentication after expiration
   */
  @Column({ name: 'refresh_token_expires', nullable: true, type: 'timestamp' })
  refresh_token_expires: Date | null;

  /**
   * Timestamp of user's last successful login
   * Used for activity tracking and security monitoring
   */
  @Column({ name: 'last_login_at', nullable: true, type: 'timestamp' })
  last_login_at: Date | null;

  // ============================================================================
  // RELATIONSHIP FIELDS
  // ============================================================================

  /**
   * Foreign key reference to user profile
   * One-to-one relationship with UserProfile entity
   * Nullable as profile creation may be optional
   */
  @Column({ name: 'profile_uuid', nullable: true, unique: true, type: 'uuid' })
  profile_uuid: string | null;

  // ============================================================================
  // TIMESTAMP FIELDS
  // ============================================================================

  /**
   * Timestamp when the user account was created
   * Auto-generated by TypeORM
   */
  @CreateDateColumn({ name: 'created_at' })
  created_at: Date;

  /**
   * Timestamp when the user account was last updated
   * Auto-updated by TypeORM on any field change
   */
  @UpdateDateColumn({ name: 'updated_at' })
  updated_at: Date;

  // ============================================================================
  // RELATIONSHIPS
  // ============================================================================

  /**
   * One-to-one relationship with UserProfile
   * Links user to their profile information
   * Join column uses profile_uuid field
   */
  @OneToOne(() => UserProfile, profile => profile.user)
  @JoinColumn({ name: 'profile_uuid', referencedColumnName: 'uuid' })
  profile: UserProfile;
}