import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn, OneToOne } from 'typeorm';
import { User } from '../../auth/entities/user.entity';

/**
 * UserProfile Entity
 * 
 * Represents a user's profile information in the database. This entity
 * stores additional user data beyond the basic authentication information,
 * including tags for categorization and flexible metadata for custom data.
 * 
 * Features:
 * - UUID primary key for unique identification
 * - Tags array for user categorization and organization
 * - JSONB metadata field for flexible data storage
 * - Automatic timestamp tracking (created_at, updated_at)
 * - One-to-one relationship with User entity
 * 
 * Database:
 * - Table name: 'user_profiles'
 * - Uses PostgreSQL-specific features (JSONB, text arrays)
 * - Automatic timestamp management
 * - Foreign key relationship with auth_users table
 * 
 * Usage:
 * - Created automatically when a user registers
 * - Updated through profile management endpoints
 * - Accessed via User entity relationship
 * - Supports flexible data storage for user preferences
 * 
 * @example
 * // Create new profile
 * const profile = new UserProfile();
 * profile.tags = ['developer', 'backend'];
 * profile.metadata = { preferences: { theme: 'dark' } };
 * 
 * @example
 * // Access via User entity
 * const user = await userRepository.findOne({ 
 *   where: { uuid: userId }, 
 *   relations: ['profile'] 
 * });
 * console.log(user.profile.tags); // ['developer', 'backend']
 */
@Entity('user_profiles')
export class UserProfile {
  /**
   * Unique identifier for the user profile
   * 
   * Auto-generated UUID primary key that uniquely identifies
   * each user profile in the system.
   * 
   * @example "123e4567-e89b-12d3-a456-426614174000"
   */
  @PrimaryGeneratedColumn('uuid')
  uuid: string;

  /**
   * User-defined tags for categorization and organization
   * 
   * Array of strings that allow users to categorize themselves
   * or their profiles. Useful for filtering, searching, and
   * organizing users by interests, skills, or other criteria.
   * 
   * Database: PostgreSQL text array with default empty array
   * Validation: Handled at service level (max 20 tags, unique, max 50 chars each)
   * 
   * @example ["developer", "backend", "typescript", "nestjs"]
   */
  @Column({ type: 'text', array: true, default: [] })
  tags: string[];

  /**
   * Flexible metadata storage for additional user data
   * 
   * JSONB field that allows storing arbitrary JSON data for
   * user preferences, profile information, or application-specific
   * data. Provides flexibility without requiring schema changes.
   * 
   * Database: PostgreSQL JSONB with default empty object
   * Validation: Handled at service level (max 10KB size)
   * 
   * Common use cases:
   * - User preferences (theme, language, notifications)
   * - Profile information (bio, location, social links)
   * - Application settings and configurations
   * - Custom user attributes and data
   * 
   * @example
   * {
   *   "preferences": { "theme": "dark", "language": "en" },
   *   "bio": "Full-stack developer passionate about clean code",
   *   "location": "Milan, Italy",
   *   "social": { "github": "username", "linkedin": "profile" }
   * }
   */
  @Column({ type: 'jsonb', default: {} })
  metadata: Record<string, any>;

  /**
   * Timestamp when the profile was created
   * 
   * Automatically set by TypeORM when the entity is first saved.
   * Used for audit trails and profile age calculations.
   * 
   * Database: PostgreSQL timestamp with timezone
   * 
   * @example "2024-01-15T10:30:00.000Z"
   */
  @CreateDateColumn({ name: 'created_at' })
  created_at: Date;

  /**
   * Timestamp when the profile was last updated
   * 
   * Automatically updated by TypeORM whenever the entity is saved.
   * Used for tracking profile changes and cache invalidation.
   * 
   * Database: PostgreSQL timestamp with timezone
   * 
   * @example "2024-01-15T11:45:00.000Z"
   */
  @UpdateDateColumn({ name: 'updated_at' })
  updated_at: Date;

  /**
   * One-to-one relationship with User entity
   * 
   * Each user profile belongs to exactly one user, and each user
   * has exactly one profile. This relationship is managed through
   * the User entity's profile_uuid foreign key.
   * 
   * Access pattern:
   * - From User: user.profile (populated via relations)
   * - From UserProfile: profile.user (populated via relations)
   * 
   * @example
   * // Access user from profile
   * const profile = await profileRepository.findOne({ 
   *   where: { uuid: profileUuid }, 
   *   relations: ['user'] 
   * });
   * console.log(profile.user.email); // "user@example.com"
   */
  @OneToOne(() => User, user => user.profile)
  user: User;
} 