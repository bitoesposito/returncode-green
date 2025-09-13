import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CookieAuthGuard } from './cookie-auth.guard';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RolesGuard } from './roles.guard';
import { SessionModule } from '../../common/modules/session.module';

/**
 * Guards Module
 * 
 * Provides authentication and authorization guards for the application.
 * Centralizes guard configuration and dependencies.
 * 
 * Features:
 * - Cookie-based authentication guard
 * - JWT-based authentication guard
 * - Role-based authorization guard
 * - JWT service configuration
 * - Session management integration
 * 
 * Exports:
 * - CookieAuthGuard: For cookie-based authentication
 * - JwtAuthGuard: For JWT header-based authentication
 * - RolesGuard: For role-based authorization
 */
@Module({
  imports: [
    ConfigModule,
    SessionModule, // Import SessionModule to make SessionService available
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRATION', '1h'),
        },
      }),
    }),
  ],
  providers: [
    CookieAuthGuard,
    JwtAuthGuard,
    RolesGuard,
  ],
  exports: [
    CookieAuthGuard,
    JwtAuthGuard,
    RolesGuard,
    JwtModule,
    ConfigModule,
  ],
})
export class GuardsModule {} 