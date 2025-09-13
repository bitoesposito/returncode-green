import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';

// Local imports
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from './entities/user.entity';
import { UserProfile } from '../users/entities/user-profile.entity';
import { MailModule } from '../common/modules/mail.module';
import { CommonModule } from '../common/modules/common.module';
import { SessionModule } from '../common/modules/session.module';
import { CookieAuthInterceptor } from './interceptors/cookie-auth.interceptor';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GuardsModule } from './guards/guards.module';

/**
 * Auth Module
 * 
 * Core authentication and authorization module for the application.
 * Provides comprehensive user authentication, JWT token management,
 * and role-based access control functionality.
 * 
 * Features:
 * - User registration and login
 * - JWT token generation and validation
 * - Email verification system
 * - Password reset functionality
 * - Role-based access control
 * - Audit logging for security events
 * 
 * Dependencies:
 * - TypeORM for database operations
 * - JWT for token management
 * - Passport for authentication strategies
 * - MailModule for email notifications
 * - CommonModule for shared services
 * 
 * Security:
 * - Password hashing with bcrypt
 * - JWT token expiration and rotation
 * - Rate limiting and account lockout
 * - Comprehensive audit logging
 * 
 * Exports:
 * - AuthService for authentication logic
 * - RolesGuard for route protection
 */
@Module({
  imports: [
    // Database configuration for User and UserProfile entities
    TypeOrmModule.forFeature([User, UserProfile]),
    
    // JWT configuration with async options from environment
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        // JWT secret from environment variables
        secret: configService.get<string>('JWT_SECRET'),
        // Token signing options
        signOptions: {
          // Token expiration time (default: 1 hour)
          expiresIn: configService.get<string>('JWT_EXPIRATION', '1h'),
        },
      }),
    }),
    
    // Passport module for authentication strategies
    PassportModule,
    
    // Mail module for email notifications
    MailModule,
    
    // Common module for shared services (audit, etc.)
    CommonModule,
    
    // Session module for session management
    SessionModule,
    
    // Guards module for authentication and authorization
    GuardsModule,
  ],
  
  // Controllers that handle HTTP requests
  controllers: [AuthController],
  
  // Service providers for business logic
  providers: [
    AuthService,      // Core authentication service
    JwtStrategy,      // JWT authentication strategy
    CookieAuthInterceptor, // Cookie authentication interceptor
  ],
  
  // Exports for use in other modules
  exports: [
    AuthService,      // Export for other modules to use authentication
    GuardsModule,     // Export guards module for other modules
  ],
})
export class AuthModule {}