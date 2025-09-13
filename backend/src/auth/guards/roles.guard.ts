import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

// Local imports
import { UserRole, ROLES_KEY } from '../auth.interface';

/**
 * Roles Guard
 * 
 * Implements role-based access control (RBAC) for route protection.
 * Checks if the authenticated user has the required roles to access
 * a specific route or controller.
 * 
 * Features:
 * - Role-based route protection
 * - Metadata-driven configuration
 * - Flexible role requirements
 * - Integration with JWT authentication
 * 
 * Usage:
 * - Apply to routes: @Roles(UserRole.admin)
 * - Apply to controllers: @Roles(UserRole.admin, UserRole.user)
 * - Use with JWT guard: @UseGuards(JwtAuthGuard, RolesGuard)
 * 
 * Security:
 * - Validates user roles against route requirements
 * - Supports multiple required roles (OR logic)
 * - Gracefully handles missing role requirements
 * 
 * @example
 * // Single role requirement
 * @Get('admin-only')
 * @Roles(UserRole.admin)
 * @UseGuards(JwtAuthGuard, RolesGuard)
 * adminOnly() { ... }
 * 
 * @example
 * // Multiple role requirements (OR logic)
 * @Get('user-or-admin')
 * @Roles(UserRole.admin, UserRole.user)
 * @UseGuards(JwtAuthGuard, RolesGuard)
 * userOrAdmin() { ... }
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  /**
   * Determines if the current user can access the route based on their role
   * 
   * Implements the CanActivate interface to provide role-based access control.
   * Checks route metadata for required roles and validates user permissions.
   * 
   * Process:
   * 1. Extract required roles from route/controller metadata
   * 2. Allow access if no roles are required (public route)
   * 3. Extract user information from request
   * 4. Check if user has any of the required roles
   * 
   * @param context - Execution context containing request and metadata information
   * @returns boolean - True if user has required role(s), false otherwise
   * 
   * @example
   * // Route with admin role requirement
   * @Get('admin')
   * @Roles(UserRole.admin)
   * @UseGuards(JwtAuthGuard, RolesGuard)
   * adminRoute() { ... }
   * 
   * @example
   * // Controller with role requirement for all routes
   * @Controller('admin')
   * @Roles(UserRole.admin)
   * @UseGuards(JwtAuthGuard, RolesGuard)
   * export class AdminController { ... }
   */
  canActivate(context: ExecutionContext): boolean {
    // Extract required roles from route metadata
    // Checks both method-level and class-level metadata
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),  // Method-level metadata
      context.getClass(),    // Class-level metadata
    ]);

    // If no roles are required, allow access (public route)
    if (!requiredRoles) {
      return true;
    }

    // Extract user information from the request
    // User object is added by JwtAuthGuard during authentication
    const { user } = context.switchToHttp().getRequest();
    
    // Check if user has any of the required roles (OR logic)
    // Returns true if user's role matches any required role
    return requiredRoles.some((role) => user?.role === role);
  }
} 