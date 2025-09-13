import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { SessionService } from '../../common/services/session.service';

/**
 * Cookie Authentication Guard
 * 
 * Validates JWT tokens from httpOnly cookies instead of Authorization header.
 * Provides secure authentication for cookie-based token management.
 * 
 * Features:
 * - Extracts JWT token from httpOnly cookies
 * - Validates token signature and expiration
 * - Adds user data to request object
 * - Handles missing or invalid tokens gracefully
 * 
 * Security:
 * - Uses httpOnly cookies for XSS protection
 * - Validates token signature
 * - Checks token expiration
 * - Provides detailed error logging
 */
@Injectable()
export class CookieAuthGuard implements CanActivate {
  private readonly logger = new Logger(CookieAuthGuard.name);
  constructor(
    private jwtService: JwtService,
    private sessionService: SessionService // Inject SessionService
  ) {}

  /**
   * Validate authentication from cookies
   * 
   * Extracts and validates JWT token from httpOnly cookies.
   * Adds user information to request object if authentication succeeds.
   * 
   * @param context - Execution context with request information
   * @returns Promise<boolean> - True if authentication succeeds
   * 
   * @throws UnauthorizedException - If token is missing or invalid
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromCookies(request);

    if (!token) {
      this.logger.warn('No authentication token found in cookies');
      throw new UnauthorizedException('No authentication token found in cookies');
    }

    try {
      const payload = await this.jwtService.verifyAsync(token);
      // Validate sessionId in SessionService
      if (!payload.sessionId) {
        this.logger.warn('No sessionId in token', payload);
        throw new UnauthorizedException('No sessionId in token');
      }
      const session = await this.sessionService.validateSession(payload.sessionId, token);
      if (!session) {
        this.logger.warn('Session is not valid or expired', { sessionId: payload.sessionId });
        throw new UnauthorizedException('Session is not valid or expired');
      }
      // Attach user and sessionId to request
      const userObject = { 
        uuid: payload.sub,  // Map 'sub' to 'uuid' for consistency
        email: payload.email,
        role: payload.role,
        sessionId: payload.sessionId,
        iat: payload.iat
      };
      request['user'] = userObject;
      return true;
    } catch (error) {
      this.logger.error('Invalid authentication token', { error });
      throw new UnauthorizedException('Invalid authentication token');
    }
  }

  /**
   * Extract JWT token from cookies
   * 
   * Looks for the access token in the request cookies.
   * 
   * @param request - Express request object
   * @returns string | undefined - JWT token or undefined if not found
   */
  private extractTokenFromCookies(request: Request): string | undefined {
    const cookies = request.cookies;
    return cookies?.access_token;
  }
} 