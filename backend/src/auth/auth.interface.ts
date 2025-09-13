import { IsEmail, IsString, MinLength, MaxLength, Matches, IsNotEmpty } from 'class-validator';
import { SetMetadata } from '@nestjs/common';

/**
 * Auth Module Interfaces and Types
 * 
 * This file contains all the interfaces, enums, and types used by the auth module.
 * Includes role definitions, JWT payload structure, and security configurations.
 */

// ============================================================================
// ROLE AND AUTHORIZATION TYPES
// ============================================================================

/**
 * Enum defining the available user roles in the system
 * 
 * Used for role-based access control (RBAC) throughout the application.
 * Each role has specific permissions and access levels.
 */
export enum UserRole {
  /** Administrator role with full system access */
  admin = 'admin',
  /** Standard user role with limited access */
  user = 'user',
}

/**
 * Metadata key used for storing roles in route metadata
 * 
 * Used by the RolesGuard to extract required roles from route decorators.
 * This key is used with NestJS's SetMetadata function.
 */
export const ROLES_KEY = 'roles';

/**
 * Decorator for specifying required roles for a route or controller
 * 
 * Used to protect routes with role-based access control.
 * Can be applied to individual methods or entire controllers.
 * Supports multiple roles (OR logic - user needs any of the specified roles).
 * 
 * @param roles - Array of UserRole values that can access the route
 * 
 * @example
 * // Single role requirement
 * @Roles(UserRole.admin)
 * @UseGuards(JwtAuthGuard, RolesGuard)
 * adminOnly() { ... }
 * 
 * @example
 * // Multiple role requirements (OR logic)
 * @Roles(UserRole.admin, UserRole.user)
 * @UseGuards(JwtAuthGuard, RolesGuard)
 * userOrAdmin() { ... }
 */
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);

// ============================================================================
// JWT AND AUTHENTICATION INTERFACES
// ============================================================================

/**
 * Interface for JWT payload structure
 * 
 * Defines the structure of data stored in JWT tokens.
 * This payload is used for user identification and authorization.
 * 
 * Security:
 * - Contains minimal necessary user information
 * - Uses UUID for user identification
 * - Includes role for authorization decisions
 * - Includes sessionId for session management
 */
export interface JwtPayload {
  /** User UUID - unique identifier for the user */
  sub: string;
  /** User email address for identification */
  email: string;
  /** User role for authorization decisions */
  role: UserRole;
  /** Session ID for session management */
  sessionId?: string;
  /** Token type (access or refresh) */
  type?: string;
  /** Token issued at timestamp (optional, added by JWT library) */
  iat?: number;
}

/**
 * Interface for login response structure
 * 
 * Defines the complete response structure returned after successful login.
 * Includes authentication tokens and user information.
 * 
 * Features:
 * - Access and refresh tokens for session management
 * - Complete user information
 * - Profile data when available
 * - Token expiration information
 */
export interface LoginResponse {
  /** JWT access token for API authentication */
  access_token: string;
  /** JWT refresh token for token renewal */
  refresh_token: string;
  /** Session ID for session management */
  session_id: string;
  /** Token expiration time in seconds */
  expires_in: number;
  /** Complete user information */
  user: {
    /** User UUID */
    uuid: string;
    /** User email address */
    email: string;
    /** User role for authorization */
    role: UserRole;
    /** Whether the user account is active */
    is_active: boolean;
    /** Whether the user's email has been verified */
    is_verified: boolean;
    /** Whether the user has completed initial setup */
    is_configured: boolean;
    /** Last login timestamp */
    last_login_at: string;
  };
  /** User profile information (optional) */
  profile?: {
    /** Profile UUID */
    uuid: string;
    /** User tags/categories */
    tags?: string[];
  };
}

// ============================================================================
// SECURITY AND RATE LIMITING INTERFACES
// ============================================================================

/**
 * Interface for tracking login attempts
 * 
 * Used for implementing rate limiting and account lockout functionality.
 * Tracks failed login attempts to prevent brute force attacks.
 */
export interface LoginAttempt {
  /** Number of failed login attempts */
  count: number;
  /** Timestamp of the last attempt */
  timestamp: number;
  /** Timestamp until which the account is locked (optional) */
  lockedUntil?: number;
}

/**
 * Interface for security configuration
 * 
 * Defines security parameters for rate limiting and account protection.
 * Used to configure login attempt limits and lockout durations.
 */
export interface SecurityConfig {
  /** Maximum number of failed login attempts before lockout */
  maxLoginAttempts: number;
  /** Duration of account lockout in milliseconds */
  lockoutDuration: number;
  /** Time window for rate limiting in milliseconds */
  rateLimitWindow: number;
  /** Maximum number of requests allowed per time window */
  maxRequestsPerWindow: number;
}