import { Body, Controller, Get, Put, HttpCode, HttpStatus, UseGuards, Req } from '@nestjs/common';
import { CookieAuthGuard } from '../auth/guards/cookie-auth.guard';
import { UpdateProfileDto } from './users.dto';
import { ApiResponseDto } from '../common/common.interface';
import { UsersService } from './users.service';

/**
 * Users Controller
 * 
 * Provides REST API endpoints for user profile management and operations.
 * Handles profile retrieval, updates, and data validation with comprehensive
 * security measures and audit logging.
 * 
 * Features:
 * - User profile retrieval and display
 * - Profile data updates with validation
 * - Comprehensive input sanitization
 * - Audit logging for all profile changes
 * - IP address tracking for security
 * - JWT authentication protection
 * 
 * Security:
 * - All endpoints require JWT authentication
 * - Input validation and sanitization
 * - Audit logging for profile changes
 * - IP address tracking for security monitoring
 * - Rate limiting should be applied in production
 * 
 * Endpoints:
 * - GET /profile - Retrieve current user's profile
 * - PUT /profile - Update current user's profile data
 * 
 * Validation:
 * - Tags: Array validation, uniqueness, length limits
 * - Metadata: Object validation, size limits
 * - Input sanitization and filtering
 * - Comprehensive error handling
 * 
 * Usage:
 * - Used by authenticated users for profile management
 * - Provides profile data access and modification
 * - Supports flexible user data storage
 * - Enables user customization and preferences
 * 
 * @example
 * // Get user profile
 * GET /profile
 * Response: { uuid: "...", tags: [...], metadata: {...}, ... }
 * 
 * @example
 * // Update profile
 * PUT /profile
 * Body: { tags: ["developer", "backend"], metadata: { theme: "dark" } }
 * Response: { uuid: "...", tags: [...], metadata: {...}, ... }
 */
@Controller('profile')
export class UsersController {
    constructor(
        private readonly usersService: UsersService
    ) { }

    // ============================================================================
    // PROFILE MANAGEMENT ENDPOINTS
    // ============================================================================

    /**
     * Retrieve current user's profile
     * 
     * Returns the complete profile information for the authenticated user,
     * including tags, metadata, and timestamps. This endpoint provides
     * access to all user profile data for display and management purposes.
     * 
     * Features:
     * - Complete profile data retrieval
     * - Tags array with user categorizations
     * - Metadata object with flexible user data
     * - Creation and update timestamps
     * - Profile UUID for identification
     * 
     * @param req - Authenticated request containing user information
     * @returns Promise with user profile data
     * 
     * @example
     * // Request
     * GET /profile
     * 
     * // Response
     * {
     *   "http_status_code": 200,
     *   "success": true,
     *   "message": "Profile retrieved successfully",
     *   "data": {
     *     "uuid": "123e4567-e89b-12d3-a456-426614174000",
     *     "tags": ["developer", "backend", "typescript"],
     *     "metadata": {
     *       "preferences": { "theme": "dark", "language": "en" },
     *       "bio": "Full-stack developer",
     *       "location": "Milan, Italy"
     *     },
     *     "created_at": "2024-01-15T10:30:00.000Z",
     *     "updated_at": "2024-01-15T11:45:00.000Z"
     *   }
     * }
     * 
     * @throws NotFoundException if user or profile not found
     */
    @Get()
    @UseGuards(CookieAuthGuard)
    async getProfile(@Req() req: any): Promise<ApiResponseDto<any>> {
        return this.usersService.getProfile(req.user.uuid);
    }

    /**
     * Update current user's profile data
     * 
     * Updates the authenticated user's profile with new tags and/or metadata.
     * Supports partial updates, allowing users to modify only specific fields
     * while preserving existing data in other fields.
     * 
     * Features:
     * - Partial updates (tags and/or metadata)
     * - Comprehensive input validation
     * - Data sanitization and filtering
     * - Metadata merging (not replacement)
     * - Audit logging for changes
     * - IP address tracking
     * 
     * Validation Rules:
     * - Tags: Array of strings, max 20 tags, unique values, max 50 chars each
     * - Metadata: JSON object, max 10KB size, must be valid object
     * - Empty or whitespace-only tags are filtered out
     * - Metadata is merged with existing data
     * 
     * @param updateProfileDto - Profile update data with validation
     * @param req - Authenticated request containing user information
     * @returns Promise with updated profile data
     * 
     * @example
     * // Request - Update tags only
     * PUT /profile
     * {
     *   "tags": ["developer", "backend", "typescript", "nestjs"]
     * }
     * 
     * @example
     * // Request - Update metadata only
     * PUT /profile
     * {
     *   "metadata": {
     *     "preferences": { "theme": "dark", "notifications": true },
     *     "bio": "Passionate developer",
     *     "location": "Italy"
     *   }
     * }
     * 
     * @example
     * // Request - Update both fields
     * PUT /profile
     * {
     *   "tags": ["developer", "fullstack"],
     *   "metadata": {
     *     "skills": ["JavaScript", "TypeScript", "Node.js"],
     *     "experience": "5+ years"
     *   }
     * }
     * 
     * // Response
     * {
     *   "http_status_code": 200,
     *   "success": true,
     *   "message": "Profile updated successfully",
     *   "data": {
     *     "uuid": "123e4567-e89b-12d3-a456-426614174000",
     *     "tags": ["developer", "fullstack"],
     *     "metadata": {
     *       "preferences": { "theme": "dark", "notifications": true },
     *       "bio": "Passionate developer",
     *       "location": "Italy",
     *       "skills": ["JavaScript", "TypeScript", "Node.js"],
     *       "experience": "5+ years"
     *     },
     *     "created_at": "2024-01-15T10:30:00.000Z",
     *     "updated_at": "2024-01-15T12:00:00.000Z"
     *   }
     * }
     * 
     * @throws NotFoundException if user or profile not found
     * @throws BadRequestException if validation fails
     */
    @Put()
    @HttpCode(HttpStatus.OK)
    @UseGuards(CookieAuthGuard)
    async updateProfile(@Body() updateProfileDto: UpdateProfileDto, @Req() req: any): Promise<ApiResponseDto<any>> {
        return this.usersService.updateProfile(req.user.uuid, updateProfileDto, req);
    }
} 