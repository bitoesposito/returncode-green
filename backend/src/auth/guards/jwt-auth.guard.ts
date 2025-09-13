import { Injectable, ExecutionContext, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * JWT Authentication Guard
 * 
 * Extends Passport's AuthGuard to protect routes requiring JWT authentication.
 * Uses the 'jwt' strategy defined in JwtStrategy for token validation.
 * 
 * Features:
 * - Validates JWT tokens from Authorization header
 * - Logs authentication attempts and results
 * - Provides detailed error information
 * - Integrates with NestJS execution context
 * 
 * Usage:
 * - Apply to individual routes: @UseGuards(JwtAuthGuard)
 * - Apply to controllers: @UseGuards(JwtAuthGuard)
 * - Often used in combination with RolesGuard
 * 
 * Security:
 * - Validates token signature and expiration
 * - Extracts user information from token payload
 * - Handles authentication failures gracefully
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtAuthGuard.name);

  /**
   * Determines if the request can be activated
   * 
   * Overrides the parent canActivate method to add custom logging
   * and request analysis before delegating to the JWT strategy.
   * 
   * Process:
   * 1. Extract request information from execution context
   * 2. Log request details for debugging and monitoring
   * 3. Delegate authentication to parent class (JWT strategy)
   * 
   * @param context - Execution context containing request information
   * @returns Promise<boolean> - True if request is authorized, false otherwise
   * 
   * @example
   * // Applied to a route
   * @Get('protected')
   * @UseGuards(JwtAuthGuard)
   * getProtectedData() { ... }
   */
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    // Delegate to parent class for actual JWT validation
    return super.canActivate(context);
  }

  /**
   * Handles the result of JWT authentication
   * 
   * Called by Passport after JWT validation attempt.
   * Provides custom error handling and success logging.
   * 
   * Process:
   * 1. Check for authentication errors or missing user
   * 2. Log authentication failure with details
   * 3. Log successful authentication with user info
   * 4. Return user object or throw appropriate error
   * 
   * @param err - Error from JWT validation (if any)
   * @param user - User object extracted from JWT payload (if valid)
   * @param info - Additional information about the authentication attempt
   * @returns User object if authentication successful
   * @throws Error if authentication fails
   * 
   * @example
   * // This method is called automatically by Passport
   * // after JWT validation in canActivate()
   */
  handleRequest(err: any, user: any, info: any) {
    // Check for authentication failure
    if (err || !user) {
      this.logger.error('JWT Guard - Authentication failed', {
        error: err?.message,
        info: info?.message,
        hasUser: !!user
      });
      
      // Throw the original error or a generic authentication error
      throw err || new Error('Authentication failed');
    }

    // Return the user object for use in the route handler
    return user;
  }
}