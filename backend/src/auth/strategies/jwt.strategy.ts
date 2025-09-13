import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

// Local imports
import { JwtPayload } from '../auth.interface';

/**
 * JWT Strategy
 * 
 * Passport strategy for JWT token validation and user authentication.
 * Handles the extraction and validation of JWT tokens from HTTP requests.
 * 
 * Features:
 * - Bearer token extraction from Authorization header
 * - JWT signature validation using environment secret
 * - Token expiration validation
 * - User payload extraction and transformation
 * 
 * Configuration:
 * - Uses JWT_SECRET from environment variables
 * - Extracts tokens from 'Bearer <token>' format
 * - Validates token expiration automatically
 * 
 * Security:
 * - Validates token signature against secret
 * - Checks token expiration
 * - Extracts user information securely
 * - Throws error if JWT_SECRET is not configured
 * 
 * Integration:
 * - Used by JwtAuthGuard for route protection
 * - Integrates with Passport.js authentication flow
 * - Provides user object to route handlers
 * 
 * @example
 * // Strategy is automatically used by JwtAuthGuard
 * @Get('protected')
 * @UseGuards(JwtAuthGuard)
 * getProtectedData(@Req() req) {
 *   // req.user contains the validated user object
 *   return { userId: req.user.uuid, role: req.user.role };
 * }
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    // Validate JWT secret configuration
    const secret = configService.get<string>('JWT_SECRET');
    if (!secret) {
      throw new Error('JWT_SECRET is not defined in environment variables');
    }
    
    // Configure Passport JWT strategy
    super({
      // Extract JWT from Authorization header as Bearer token
      // Format: Authorization: Bearer <jwt_token>
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      
      // Don't ignore expired tokens - enforce expiration
      ignoreExpiration: false,
      
      // Get JWT secret from environment variables for signature validation
      secretOrKey: secret,
    });
  }

  /**
   * Validates the JWT payload and returns user information
   * 
   * Called by Passport after successful JWT validation.
   * Transforms the JWT payload into a user object that will be
   * available in route handlers via the request object.
   * 
   * Process:
   * 1. Receives validated JWT payload from Passport
   * 2. Extracts user information from payload
   * 3. Returns user object for use in route handlers
   * 
   * @param payload - The decoded and validated JWT payload
   * @returns Object containing user information for route handlers
   * 
   * @example
   * // JWT payload structure
   * {
   *   sub: "user-uuid",
   *   email: "user@example.com",
   *   role: "user",
   *   iat: 1234567890,
   *   exp: 1234567890
   * }
   * 
   * @example
   * // Returned user object structure
   * {
   *   uuid: "user-uuid",
   *   email: "user@example.com",
   *   role: "user",
   *   iat: 1234567890
   * }
   */
  async validate(payload: JwtPayload) {
    // Transform JWT payload into user object
    // This object will be available as req.user in route handlers
    return {
      sub: payload.sub,         // User UUID from JWT subject
      email: payload.email,     // User email from JWT payload
      role: payload.role,       // User role from JWT payload
      sessionId: payload.sessionId, // Session ID from JWT payload
      iat: payload.iat,         // Token issued at timestamp
    };
  }
}