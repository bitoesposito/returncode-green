import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

// Local imports
import { SessionService } from '../services/session.service';
import { User } from '../../auth/entities/user.entity';
import { SessionLog } from '../entities/session-log.entity';
import { SecurityLog } from '../entities/security-log.entity';
import { LoggerService } from '../services/logger.service';

/**
 * Session Module
 * 
 * Provides user session management functionality including session creation,
 * validation, and cleanup. Handles user authentication state and session data.
 * 
 * Features:
 * - User session management
 * - Session token generation and validation
 * - Session cleanup and expiration
 * - User authentication state tracking
 * - Session security and validation
 * 
 * Services:
 * - SessionService: Core session management functionality
 * - LoggerService: Session event logging
 * 
 * Dependencies:
 * - TypeOrmModule: For database operations with User entity
 * - JwtModule: For JWT token generation and validation
 * - ConfigService: For JWT configuration
 * 
 * Database Entities:
 * - User: For user session data and authentication state
 * 
 * Configuration:
 * - JWT secret key
 * - Token expiration times
 * - Session timeout settings
 * - Security policies
 * 
 * Usage:
 * - Imported by other modules for session management
 * - Used for user authentication state tracking
 * - Provides secure session handling
 */
@Module({
  // Import required modules for functionality
  imports: [
    // Database configuration for User, SessionLog, and SecurityLog entities
    TypeOrmModule.forFeature([User, SessionLog, SecurityLog]),
    
    // JWT configuration with async options
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
  ],
  
  // Service providers for session management
  providers: [
    SessionService,   // Core session management service
    LoggerService,    // Session event logging service
  ],
  
  // Export service for use in other modules
  exports: [
    SessionService,   // Session management functionality
  ],
})
export class SessionModule {} 