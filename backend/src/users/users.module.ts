import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { User } from '../auth/entities/user.entity';
import { UserProfile } from './entities/user-profile.entity';
import { CommonModule } from '../common/modules/common.module';
import { GuardsModule } from '../auth/guards/guards.module';

/**
 * Users Module
 * 
 * Provides user profile management functionality for the application.
 * Handles user profile data, including tags, metadata, and profile
 * operations with comprehensive validation and audit logging.
 * 
 * Features:
 * - User profile retrieval and management
 * - Profile data validation and sanitization
 * - Tags management with validation rules
 * - Metadata storage and management
 * - Comprehensive audit logging for profile changes
 * - IP address tracking for security
 * 
 * Services:
 * - UsersService: Core user profile operations
 * - UsersController: REST API endpoints for profile management
 * 
 * Dependencies:
 * - TypeOrmModule: Database operations and entity management
 * - CommonModule: Shared services (audit, logging, etc.)
 * - User and UserProfile entities for data management
 * 
 * Profile Features:
 * - Tags: Array of user-defined tags with validation
 * - Metadata: Flexible JSON storage for additional data
 * - Timestamps: Automatic creation and update tracking
 * - Validation: Comprehensive input validation and sanitization
 * 
 * Security:
 * - JWT authentication required for all endpoints
 * - Input validation and sanitization
 * - Audit logging for all profile changes
 * - IP address tracking for security monitoring
 * 
 * Exports:
 * - UsersService: For use in other modules that need profile functionality
 * 
 * Usage:
 * - Imported in AppModule for user profile features
 * - Provides profile management endpoints
 * - Handles user data validation and storage
 * - Manages profile lifecycle operations
 * 
 * @example
 * // In AppModule
 * imports: [
 *   UsersModule,
 *   // other modules...
 * ]
 * 
 * @example
 * // In another service
 * constructor(
 *   private usersService: UsersService
 * ) {}
 * 
 * // Get user profile
 * const profile = await this.usersService.getProfile(userId);
 * 
 * // Update profile
 * const updated = await this.usersService.updateProfile(userId, updateData, request);
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([User, UserProfile]),
    CommonModule,
    GuardsModule,
  ],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {} 