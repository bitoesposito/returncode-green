import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ApiResponseDto } from '../common/common.interface';
import { User } from '../auth/entities/user.entity';
import { UserProfile } from './entities/user-profile.entity';
import { UpdateProfileDto } from './users.dto';
import { AuditService } from '../common/services/audit.service';

/**
 * Users Service
 * 
 * Core service responsible for user profile management and operations.
 * Provides comprehensive profile data handling, validation, and audit
 * logging for user profile lifecycle management.
 * 
 * Features:
 * - User profile retrieval and display
 * - Profile data updates with validation
 * - Comprehensive input sanitization
 * - Tags management with validation rules
 * - Metadata storage and management
 * - Audit logging for all profile changes
 * - IP address tracking for security
 * 
 * Validation Rules:
 * - Tags: Array of strings, max 20 tags, unique values, max 50 chars each
 * - Metadata: JSON object, max 10KB size, must be valid object
 * - Input sanitization and filtering
 * - Comprehensive error handling
 * 
 * Security Features:
 * - Input validation and sanitization
 * - Audit logging for all operations
 * - IP address tracking for security monitoring
 * - Data size limits to prevent abuse
 * - Duplicate prevention for tags
 * 
 * Dependencies:
 * - TypeORM repositories for data access
 * - AuditService for comprehensive logging
 * - Express Request for IP extraction
 * 
 * Usage:
 * - Injected into UsersController for API endpoints
 * - Used for profile data management
 * - Provides validation and sanitization
 * - Handles audit logging and security
 * 
 * @example
 * // Get user profile
 * const profile = await usersService.getProfile(userId);
 * 
 * @example
 * // Update profile
 * const updated = await usersService.updateProfile(userId, updateData, request);
 */
@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(UserProfile)
    private readonly userProfileRepository: Repository<UserProfile>,
    private readonly auditService: AuditService
  ) { }

  // ============================================================================
  // PROFILE MANAGEMENT METHODS
  // ============================================================================

  /**
   * Get user profile by user ID
   * 
   * Retrieves the complete profile information for a specific user,
   * including tags, metadata, and timestamps. Validates that both
   * the user and their profile exist before returning data.
   * 
   * Process:
   * 1. Validates user exists in the system
   * 2. Retrieves user with profile relation
   * 3. Validates profile exists for the user
   * 4. Prepares and returns profile data
   * 5. Logs successful retrieval
   * 
   * Features:
   * - Complete profile data retrieval
   * - Tags array with user categorizations
   * - Metadata object with flexible user data
   * - Creation and update timestamps
   * - Profile UUID for identification
   * - Comprehensive error handling
   * 
   * @param userId - Unique identifier of the user
   * @returns Promise<ApiResponseDto<any>> User profile data
   * 
   * @example
   * const profile = await usersService.getProfile('user-uuid');
   * // Returns: { uuid: "...", tags: [...], metadata: {...}, created_at: "...", updated_at: "..." }
   * 
   * @throws NotFoundException if user not found
   * @throws NotFoundException if user profile not found
   * @throws Error if database operation fails
   */
  async getProfile(userId: string): Promise<ApiResponseDto<any>> {
    try {
  

      // Find user with profile relation
      const user = await this.userRepository.findOne({
        where: { uuid: userId },
        relations: ['profile']
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      if (!user.profile) {
        throw new NotFoundException('User profile not found');
      }

      // Prepare response data with proper defaults
      const profileData = {
        uuid: user.profile.uuid,
        tags: user.profile.tags || [],
        metadata: user.profile.metadata || {},
        created_at: user.profile.created_at,
        updated_at: user.profile.updated_at
      };

              this.logger.log('Profile retrieved successfully', { userId });
      
      return ApiResponseDto.success(profileData, 'Profile retrieved successfully');
    } catch (error) {
      this.logger.error('Failed to get user profile', { userId, error: error.message });
      throw error;
    }
  }

  /**
   * Update user profile data
   * 
   * Updates the user's profile with new tags and/or metadata. Supports
   * partial updates, allowing users to modify only specific fields while
   * preserving existing data in other fields. Includes comprehensive
   * validation and audit logging.
   * 
   * Process:
   * 1. Validates user and profile exist
   * 2. Validates input data using validation rules
   * 3. Updates profile fields with sanitization
   * 4. Saves updated profile to database
   * 5. Logs profile update for audit
   * 6. Returns updated profile data
   * 
   * Features:
   * - Partial updates (tags and/or metadata)
   * - Comprehensive input validation
   * - Data sanitization and filtering
   * - Metadata merging (not replacement)
   * - Tags deduplication and filtering
   * - Audit logging for changes
   * - IP address tracking
   * 
   * Validation Rules:
   * - Tags: Array of strings, max 20 tags, unique values, max 50 chars each
   * - Metadata: JSON object, max 10KB size, must be valid object
   * - Empty or whitespace-only tags are filtered out
   * - Metadata is merged with existing data
   * 
   * @param userId - Unique identifier of the user
   * @param updateProfileDto - Profile update data with validation
   * @param req - Request object for IP extraction and audit logging
   * @returns Promise<ApiResponseDto<any>> Updated profile data
   * 
   * @example
   * const updateData = { tags: ['developer', 'backend'], metadata: { theme: 'dark' } };
   * const updated = await usersService.updateProfile('user-uuid', updateData, request);
   * // Returns: { uuid: "...", tags: [...], metadata: {...}, created_at: "...", updated_at: "..." }
   * 
   * @throws NotFoundException if user not found
   * @throws NotFoundException if user profile not found
   * @throws BadRequestException if validation fails
   * @throws Error if database operation fails
   */
  async updateProfile(userId: string, updateProfileDto: UpdateProfileDto, req?: any): Promise<ApiResponseDto<any>> {
    try {
  

      // Find user with profile relation
      const user = await this.userRepository.findOne({
        where: { uuid: userId },
        relations: ['profile']
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      if (!user.profile) {
        throw new NotFoundException('User profile not found');
      }

      // Validate input data before processing
      this.validateProfileData(updateProfileDto);

      // Update profile fields with proper sanitization
      if (updateProfileDto.tags !== undefined) {
        // Ensure tags is an array and filter out empty values
        user.profile.tags = Array.isArray(updateProfileDto.tags) 
          ? updateProfileDto.tags.filter(tag => tag && tag.trim().length > 0)
          : [];
      }

      if (updateProfileDto.metadata !== undefined) {
        // Merge existing metadata with new metadata (not replacement)
        user.profile.metadata = {
          ...user.profile.metadata,
          ...updateProfileDto.metadata
        };
      }

      // Save updated profile to database
      const updatedProfile = await this.userProfileRepository.save(user.profile);

      // Prepare response data with proper defaults
      const profileData = {
        uuid: updatedProfile.uuid,
        tags: updatedProfile.tags || [],
        metadata: updatedProfile.metadata || {},
        created_at: updatedProfile.created_at,
        updated_at: updatedProfile.updated_at
      };

      this.logger.log('Profile updated successfully', { userId });
      
      // Extract IP address from request for audit logging
      const clientIp = this.getClientIp(req);

      // Log profile update for audit compliance
      await this.auditService.logProfileUpdate(userId, user.email, clientIp);
      
      return ApiResponseDto.success(profileData, 'Profile updated successfully');
    } catch (error) {
      this.logger.error('Failed to update user profile', { userId, error: error.message });
      throw error;
    }
  }

  // ============================================================================
  // VALIDATION METHODS
  // ============================================================================

  /**
   * Validate profile update data
   * 
   * Performs comprehensive validation on profile update data to ensure
   * data integrity, prevent abuse, and maintain system performance.
   * Validates both tags and metadata fields according to defined rules.
   * 
   * Validation Rules:
   * - Tags: Array of strings, max 20 tags, unique values, max 50 chars each
   * - Metadata: JSON object, max 10KB size, must be valid object
   * - Empty or whitespace-only tags are filtered out
   * - Duplicate tags are not allowed
   * - Metadata size is limited to prevent abuse
   * 
   * @param updateProfileDto - Profile update data to validate
   * @throws BadRequestException if validation fails
   * 
   * @example
   * // Valid data
   * this.validateProfileData({ 
   *   tags: ['developer', 'backend'], 
   *   metadata: { theme: 'dark' } 
   * });
   * 
   * @example
   * // Invalid data - too many tags
   * this.validateProfileData({ 
   *   tags: Array(25).fill('tag') // Will throw BadRequestException
   * });
   */
  private validateProfileData(updateProfileDto: UpdateProfileDto): void {
    // Validate tags array if provided
    if (updateProfileDto.tags !== undefined) {
      if (!Array.isArray(updateProfileDto.tags)) {
        throw new BadRequestException('Tags must be an array');
      }

      // Check maximum number of tags
      if (updateProfileDto.tags.length > 20) {
        throw new BadRequestException('Cannot have more than 20 tags');
      }

      // Check for duplicate tags (case-sensitive)
      const uniqueTags = new Set(updateProfileDto.tags);
      if (uniqueTags.size !== updateProfileDto.tags.length) {
        throw new BadRequestException('Tags must be unique');
      }

      // Validate individual tag length
      for (const tag of updateProfileDto.tags) {
        if (tag && tag.length > 50) {
          throw new BadRequestException('Individual tags cannot exceed 50 characters');
        }
      }
    }

    // Validate metadata object if provided
    if (updateProfileDto.metadata !== undefined) {
      if (typeof updateProfileDto.metadata !== 'object' || updateProfileDto.metadata === null) {
        throw new BadRequestException('Metadata must be an object');
      }

      // Check metadata size to prevent excessive data storage
      const metadataSize = JSON.stringify(updateProfileDto.metadata).length;
      if (metadataSize > 10000) { // 10KB limit
        throw new BadRequestException('Metadata size cannot exceed 10KB');
      }
    }
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Extract client IP address from request
   * 
   * Handles various proxy configurations and headers to determine the actual
   * client IP address for security logging and audit purposes.
   * 
   * Priority order:
   * 1. X-Forwarded-For header (first IP in chain)
   * 2. X-Real-IP header
   * 3. Connection remote address
   * 4. Fallback to 'Unknown'
   * 
   * @param req - Express request object containing headers and connection info
   * @returns string Client IP address or 'Unknown'
   * 
   * @example
   * const ip = this.getClientIp(request);
   * // Returns: "192.168.1.100" or "Unknown"
   */
  private getClientIp(req?: any): string {
    if (!req) return 'Unknown';
    const forwardedFor = req.headers?.['x-forwarded-for'] as string;
    const realIp = req.headers?.['x-real-ip'] as string;
    const remoteAddr = req.connection?.remoteAddress || req.socket?.remoteAddress;
    if (forwardedFor) {
      const ips = forwardedFor.split(',').map(ip => ip.trim());
      return ips[0];
    }
    if (realIp) {
      return realIp;
    }
    if (remoteAddr) {
      return remoteAddr.replace(/^::ffff:/, '');
    }
    return 'Unknown';
  }
} 