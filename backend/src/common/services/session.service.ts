import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import { SessionLog } from '../entities/session-log.entity';
import * as crypto from 'crypto';

export interface Session {
  id: string;
  userId: string;
  token: string;
  refreshToken: string;
  createdAt: Date;
  expiresAt: Date;
  lastActivity: Date;
  deviceInfo?: string;
  ipAddress?: string;
  userAgent?: string;
  isActive: boolean;
}

export interface PublicSession {
  id: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  lastActivity: Date;
  deviceInfo?: string;
  ipAddress?: string;
  userAgent?: string;
  isActive: boolean;
}

export interface CreateSessionOptions {
  userId: string;
  deviceInfo?: string;
  ipAddress?: string;
  userAgent?: string;
  rememberMe?: boolean;
}

/**
 * Session Service
 *
 * Manages user sessions and authentication tokens with persistent storage.
 * Provides comprehensive session lifecycle management including creation, validation,
 * and invalidation of user sessions. All session events are logged in the database.
 *
 * Features:
 * - Session creation with JWT and refresh tokens
 * - Session validation and expiration checking
 * - Session invalidation (single and bulk)
 * - Device information tracking
 * - Multi-device session management
 * - Session activity monitoring
 * - Integration with user repository
 * - Session event logging in DB
 *
 * Security Features:
 * - Secure token generation
 * - Session expiration management
 * - Device fingerprinting
 * - IP address tracking
 * - Activity monitoring
 * - Bulk session revocation
 *
 * Usage:
 * - Injected into authentication services
 * - Manages user login/logout sessions
 * - Provides session validation for protected routes
 * - Supports multi-device session management
 */
@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);

  /**
   * In-memory session storage for active sessions (should be Redis in production)
   */
  private readonly sessions = new Map<string, Session>();

  /**
   * Constructor with injected repositories
   * @param jwtService JWT service for token generation
   * @param userRepository Repository for User entity
   * @param sessionLogRepository Repository for SessionLog entity
   */
  constructor(
    private readonly jwtService: JwtService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(SessionLog)
    private readonly sessionLogRepository: Repository<SessionLog>,
  ) {}

  // ==========================================================================
  // SESSION CREATION AND MANAGEMENT
  // ==========================================================================

  /**
   * Create a new user session
   * @param options Session creation options
   * @returns Created session object
   */
  async createSession(options: CreateSessionOptions): Promise<Session> {
    const { userId, deviceInfo, ipAddress, userAgent, rememberMe = false } = options;


    // Verify user exists
    const user = await this.userRepository.findOne({ where: { uuid: userId } });
    if (!user) {
      throw new Error('User not found');
    }

    // Generate session ID
    const sessionId = crypto.randomUUID();

    // Generate JWT token
    const token = this.jwtService.sign({ 
      sub: userId,
      email: user.email,
      role: user.role,
      sessionId: sessionId,
      type: 'access'
    });

    // Generate refresh token
    const refreshToken = this.jwtService.sign({
      sub: userId,
      sessionId: sessionId,
      type: 'refresh'
    }, { expiresIn: rememberMe ? '30d' : '7d' });

    // Set expiration times
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (rememberMe ? 30 : 7) * 24 * 60 * 60 * 1000);

    // Create session object
    const session: Session = {
      id: sessionId,
      userId,
      token,
      refreshToken,
      createdAt: now,
      expiresAt,
      lastActivity: now,
      deviceInfo,
      ipAddress,
      userAgent,
      isActive: true,
    };

    // Store session in memory
    this.sessions.set(sessionId, session);

    // Log session creation in DB
    await this.sessionLogRepository.save(this.sessionLogRepository.create({
      eventType: 'CREATED',
      user: user,
      sessionTokenHash: crypto.createHash('sha256').update(token).digest('hex'),
      refreshTokenHash: crypto.createHash('sha256').update(refreshToken).digest('hex'),
      deviceInfo,
      ipAddress,
      userAgent,
      details: {
        sessionId: sessionId,
        userId: userId, // Store userId in details for debugging
        rememberMe: rememberMe,
        expiresAt: expiresAt.toISOString()
      },
    }));

    this.logger.log('Session created successfully', { sessionId, userId });

    return session;
  }

  /**
   * Validate if a session is active and not expired
   * @param sessionId Session ID to validate
   * @param token JWT token for additional validation
   * @returns Session object if valid, null otherwise
   */
  async validateSession(sessionId: string, token?: string): Promise<Session | null> {
    const session = this.sessions.get(sessionId);

    // Check expiration
    if (session && new Date() > session.expiresAt) {
      this.logger.warn('Session expired', { sessionId });
      await this.invalidateSession(sessionId, 'EXPIRED');
      return null;
    }

    // Update last activity
    if (session) {
      session.lastActivity = new Date();
      this.sessions.set(sessionId, session);
    }

    // Validate JWT token if provided
    if (token) {
      try {
        const payload = this.jwtService.verify(token);
        if (payload.sessionId !== sessionId) {
          this.logger.warn('SessionId mismatch in token', { sessionId, tokenSessionId: payload.sessionId });
          await this.invalidateSession(sessionId, 'TOKEN_MISMATCH');
          return null;
        }
      } catch (error) {
        this.logger.warn('Token invalid during session validation', { sessionId, error });
        await this.invalidateSession(sessionId, 'INVALID_TOKEN');
        return null;
      }
    }
    return session || null;
  }

  /**
   * Refresh a session with new tokens
   * @param sessionId Session ID to refresh
   * @param refreshToken Current refresh token
   * @returns New session object with updated tokens
   */
  async refreshSession(sessionId: string, refreshToken: string): Promise<Session | null> {
    const session = this.sessions.get(sessionId);
    
    if (!session || !session.isActive) {
      return null;
    }

    // Validate refresh token
    try {
      const payload = this.jwtService.verify(refreshToken);
      if (payload.sessionId !== sessionId || payload.type !== 'refresh') {
        await this.invalidateSession(sessionId, 'INVALID_REFRESH_TOKEN');
        return null;
      }
    } catch (error) {
      await this.invalidateSession(sessionId, 'EXPIRED_REFRESH_TOKEN');
      return null;
    }

    // Generate new tokens
    const user = await this.userRepository.findOne({ where: { uuid: session.userId } });
    if (!user) {
      await this.invalidateSession(sessionId, 'USER_NOT_FOUND');
      return null;
    }

    const newToken = this.jwtService.sign({ 
      sub: session.userId,
      email: user.email,
      role: user.role,
      sessionId: sessionId,
      type: 'access'
    });

    const newRefreshToken = this.jwtService.sign({
      sub: session.userId,
      sessionId: sessionId,
      type: 'refresh'
    }, { expiresIn: '7d' });

    // Update session
    session.token = newToken;
    session.refreshToken = newRefreshToken;
    session.lastActivity = new Date();
    this.sessions.set(sessionId, session);

    // Log refresh event
    await this.sessionLogRepository.save(this.sessionLogRepository.create({
      eventType: 'REFRESHED',
      user: user,
      sessionTokenHash: crypto.createHash('sha256').update(newToken).digest('hex'),
      refreshTokenHash: crypto.createHash('sha256').update(newRefreshToken).digest('hex'),
      deviceInfo: session.deviceInfo,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      details: {
        sessionId: sessionId,
        userId: session.userId, // Store userId in details for debugging
        previousTokenHash: crypto.createHash('sha256').update(refreshToken).digest('hex')
      },
    }));

    this.logger.log('Session refreshed successfully', { sessionId });

    return session;
  }

  /**
   * Invalidate a specific session
   * @param sessionId Session ID to invalidate
   * @param reason Reason for invalidation
   */
  async invalidateSession(sessionId: string, reason: string = 'MANUAL'): Promise<void> {
    const session = this.sessions.get(sessionId);
    
    if (session && session.isActive) {
      session.isActive = false;
      this.sessions.delete(sessionId);

      // Log session invalidation
      const user = await this.userRepository.findOne({ where: { uuid: session.userId } });
      await this.sessionLogRepository.save(this.sessionLogRepository.create({
        eventType: 'REVOKED',
        user: user || undefined,
        sessionTokenHash: crypto.createHash('sha256').update(session.token).digest('hex'),
        refreshTokenHash: crypto.createHash('sha256').update(session.refreshToken).digest('hex'),
        deviceInfo: session.deviceInfo,
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
        details: {
          sessionId: sessionId,
          reason: reason,
          invalidatedAt: new Date().toISOString(),
          userId: session.userId // Store userId in details for debugging
        },
      }));

      this.logger.log('Session invalidated', { sessionId, userId: session.userId, reason });
    } else {
      this.logger.warn('Session not found or already inactive during invalidation', { sessionId });
    }
  }

  /**
   * Invalidate all sessions for a specific user
   * @param userId User UUID
   * @param reason Reason for invalidation
   */
  async invalidateAllUserSessions(userId: string, reason: string = 'BULK_REVOKE'): Promise<void> {
    const sessionsToInvalidate = Array.from(this.sessions.entries())
      .filter(([_, session]) => session.userId === userId && session.isActive);

    for (const [sessionId, session] of sessionsToInvalidate) {
      await this.invalidateSession(sessionId, reason);
    }

    this.logger.log('All user sessions invalidated', { userId, count: sessionsToInvalidate.length, reason });
  }

  /**
   * Invalidate all sessions except the current one
   * @param userId User UUID
   * @param currentSessionId Current session ID to keep
   */
  async invalidateOtherSessions(userId: string, currentSessionId: string): Promise<void> {
    const sessionsToInvalidate = Array.from(this.sessions.entries())
      .filter(([sessionId, session]) => 
        session.userId === userId && 
        session.isActive && 
        sessionId !== currentSessionId
      );

    for (const [sessionId, session] of sessionsToInvalidate) {
      await this.invalidateSession(sessionId, 'OTHER_DEVICE_LOGIN');
    }

    this.logger.log('Other sessions invalidated', { 
      userId, 
      currentSessionId, 
      invalidatedCount: sessionsToInvalidate.length 
    });
  }

  /**
   * Get all active sessions for a user
   * @param userId User UUID
   * @returns Array of active session objects
   */
  getActiveSessions(userId: string): PublicSession[] {
    return Array.from(this.sessions.values())
      .filter(s => s.userId === userId && s.isActive)
      .map(s => ({
        id: s.id,
        userId: s.userId,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        lastActivity: s.lastActivity,
        deviceInfo: s.deviceInfo,
        ipAddress: s.ipAddress,
        userAgent: s.userAgent,
        isActive: s.isActive
      }));
  }

  /**
   * Get session by ID
   * @param sessionId Session ID
   * @returns Session object or null
   */
  getSession(sessionId: string): PublicSession | null {
    const session = this.sessions.get(sessionId);
    if (!session || !session.isActive) {
      return null;
    }
    return {
      id: session.id,
      userId: session.userId,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      lastActivity: session.lastActivity,
      deviceInfo: session.deviceInfo,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      isActive: session.isActive
    };
  }

  /**
   * Update session activity
   * @param sessionId Session ID
   */
  updateSessionActivity(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session && session.isActive) {
      session.lastActivity = new Date();
      this.sessions.set(sessionId, session);
    }
  }

  /**
   * Clean up expired sessions
   */
  async cleanupExpiredSessions(): Promise<void> {
    const now = new Date();
    const expiredSessions = Array.from(this.sessions.entries())
      .filter(([_, session]) => session.expiresAt < now);

    for (const [sessionId, session] of expiredSessions) {
      await this.invalidateSession(sessionId, 'EXPIRED');
    }

    if (expiredSessions.length > 0) {
      this.logger.log('Cleaned up expired sessions', { count: expiredSessions.length });
    }
  }

  /**
   * Get session statistics
   */
  getSessionStats(): { total: number; active: number; expired: number } {
    const sessions = Array.from(this.sessions.values());
    const now = new Date();
    
    return {
      total: sessions.length,
      active: sessions.filter(s => s.isActive).length,
      expired: sessions.filter(s => s.expiresAt < now).length
    };
  }

  /**
   * Get all active sessions for debugging
   */
  getAllActiveSessions(): Array<{ sessionId: string; session: PublicSession }> {
    return Array.from(this.sessions.entries())
      .filter(([_, session]) => session.isActive)
      .map(([sessionId, session]) => ({
        sessionId,
        session: {
          id: session.id,
          userId: session.userId,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          lastActivity: session.lastActivity,
          deviceInfo: session.deviceInfo,
          ipAddress: session.ipAddress,
          userAgent: session.userAgent,
          isActive: session.isActive
        }
      }));
  }
} 