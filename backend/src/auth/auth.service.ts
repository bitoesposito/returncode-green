import { 
  Injectable, 
  Logger, 
  UnauthorizedException, 
  ConflictException, 
  BadRequestException, 
  InternalServerErrorException,
  NotFoundException
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { Response, Request } from 'express'; // Added Response and Request import
import { HttpStatus } from '@nestjs/common';

// Local imports
import { ApiResponseDto } from '../common/common.interface';
import { User } from './entities/user.entity';
import { UserProfile } from '../users/entities/user-profile.entity';
import { LoginResponse, UserRole } from './auth.interface';
import { 
  LoginDto, 
  RegisterDto, 
  ForgotPasswordDto, 
  ResetPasswordDto, 
  VerifyEmailDto 
} from './auth.dto';
import { MailService } from '../common/services/mail.service';
import { AuditService } from '../common/services/audit.service';
import { SessionService } from '../common/services/session.service';

/**
 * Auth Service
 * 
 * Core business logic for authentication and authorization operations.
 * Handles user registration, login, token management, and security features.
 * 
 * Features:
 * - User registration with email verification
 * - Secure login with JWT token generation
 * - Token refresh and rotation
 * - Password reset via OTP
 * - Email verification system
 * - Comprehensive audit logging
 * - Security monitoring and rate limiting
 * 
 * Security:
 * - Password hashing with bcrypt (12 rounds)
 * - JWT token management with expiration
 * - OTP-based password reset
 * - IP tracking for security events
 * - Account status validation
 * 
 * Dependencies:
 * - TypeORM repositories for data access
 * - JWT service for token operations
 * - Mail service for email notifications
 * - Audit service for security logging
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(UserProfile)
    private readonly userProfileRepository: Repository<UserProfile>,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
    private readonly auditService: AuditService,
    private readonly sessionService: SessionService,
  ) {}

  // ============================================================================
  // USER REGISTRATION METHODS
  // ============================================================================

  /**
   * Register a new user account
   * 
   * Creates a new user account with comprehensive security measures.
   * Includes email verification, password hashing, and audit logging.
   * 
   * Process:
   * 1. Validates email uniqueness
   * 2. Hashes password securely
   * 3. Creates user profile
   * 4. Generates verification token
   * 5. Sends verification email
   * 6. Logs registration event
   * 
   * Security Features:
   * - Password hashing with bcrypt (12 rounds)
   * - Email verification requirement
   * - Verification token expiration (24 hours)
   * - IP tracking for audit logs
   * 
   * @param registerDto - User registration data
   * @param req - Express request object for IP tracking
   * @returns Promise with registration confirmation
   * 
   * @throws ConflictException if user already exists
   * @throws Error if registration process fails
   */
  async register(registerDto: RegisterDto, req?: any): Promise<ApiResponseDto<any>> {
    try {
      // Check if user already exists
      const existingUser = await this.userRepository.findOne({
        where: { email: registerDto.email }
      });

      if (existingUser) {
        throw new ConflictException('User with this email already exists');
      }

      // Hash password with bcrypt (12 rounds for security)
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(registerDto.password, saltRounds);

      // Generate verification token (6-digit OTP)
      const verificationToken = this.generateSecureToken();
      const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Create user profile (always create one for consistency)
      const profile = this.userProfileRepository.create({
        tags: [],
        metadata: {}
      });
      await this.userProfileRepository.save(profile);

      // Create user with all necessary fields
      const user = this.userRepository.create({
        email: registerDto.email,
        password_hash: passwordHash,
        role: UserRole.user,
        is_active: true,
        is_verified: false,
        is_configured: false,
        profile_uuid: profile.uuid,
        verification_token: verificationToken,
        verification_expires: verificationExpiry
      });

      await this.userRepository.save(user);

      // Send verification email (non-blocking)
      try {
        await this.mailService.sendVerificationEmail(registerDto.email, verificationToken);
  
      } catch (emailError) {
        this.logger.error('Failed to send verification email', { email: registerDto.email, error: emailError });
        // Don't fail registration if email fails, just log it
      }

      // Extract IP from request for audit logging
      const clientIp = this.getClientIp(req);

      // Log user registration for audit purposes
      await this.auditService.logUserRegistration(user.uuid, user.email, clientIp);


      
      return ApiResponseDto.success({
        user: {
          uuid: user.uuid,
          email: user.email,
          role: user.role,
          is_active: user.is_active,
          is_verified: user.is_verified,
          is_configured: user.is_configured,
          profile_uuid: user.profile_uuid
        }
      }, 'User registered successfully. Please check your email to verify your account.');
    } catch (error) {
      this.logger.error('Registration failed', error);
      throw error;
    }
  }

  // ============================================================================
  // AUTHENTICATION METHODS
  // ============================================================================

  /**
   * Authenticate user and generate JWT tokens
   * 
   * Authenticates user credentials and generates JWT access and refresh tokens.
   * Implements secure token storage using httpOnly cookies.
   * 
   * Process:
   * 1. Validates user credentials
   * 2. Checks account status and verification
   * 3. Creates user session
   * 4. Generates JWT tokens
   * 5. Sets secure httpOnly cookies
   * 
   * Security Features:
   * - Password hashing verification
   * - Account status validation
   * - Email verification check
   * - Secure session management
   * - httpOnly cookie storage
   * - CSRF protection
   * 
   * @param loginDto - User login credentials
   * @param response - Express response object for cookie setting
   * @returns Promise with user data and session info
   * 
   * @throws UnauthorizedException if credentials are invalid
   * @throws UnauthorizedException if account is deactivated
   * @throws UnauthorizedException if email is not verified
   * @throws Error if login process fails
   */
  async login(loginDto: LoginDto, response: Response, req?: Request): Promise<ApiResponseDto<any>> {
    try {
      // Find user by email
      const user = await this.userRepository.findOne({
        where: { email: loginDto.email },
        relations: ['profile']
      });

      // Validate user credentials
      if (!user) {
        this.logger.warn('Login attempt with invalid email', { email: loginDto.email });
        throw new UnauthorizedException('Invalid credentials');
      }

      const isPasswordValid = await bcrypt.compare(loginDto.password, user.password_hash);
      if (!isPasswordValid) {
        this.logger.warn('Login attempt with invalid password', { email: loginDto.email });
        throw new UnauthorizedException('Invalid credentials');
      }

      if (!user.is_active) {
        this.logger.warn('Login attempt for deactivated account', { email: loginDto.email });
        throw new UnauthorizedException('Account is deactivated');
      }

      if (!user.is_verified) {
        this.logger.warn('Login attempt for unverified email', { email: loginDto.email });
        throw new UnauthorizedException('Email not verified');
      }

      // Get client information
      const ipAddress = req?.headers['x-forwarded-for']?.toString() || req?.socket?.remoteAddress || 'unknown';
      const userAgent = req?.headers['user-agent'] || 'unknown';
      const deviceInfo = this.getDeviceInfo(userAgent);

      // Update last login timestamp
      user.last_login_at = new Date();
      await this.userRepository.save(user);

      // Create session
      let session;
      try {
        session = await this.sessionService.createSession({
          userId: user.uuid,
          deviceInfo,
          ipAddress,
          userAgent,
          rememberMe: loginDto.rememberMe || false
        });
      } catch (sessionError) {
        this.logger.error('Failed to create user session', { userId: user.uuid });
        throw new InternalServerErrorException('Failed to create session');
      }

      // Invalidate other sessions if remember_me is false
      if (!loginDto.rememberMe) {
        await this.sessionService.invalidateOtherSessions(user.uuid, session.id);
        
      }

      // Set cookies
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict' as const,
        path: '/',
        domain: process.env.COOKIE_DOMAIN || undefined
      };

      response.cookie('access_token', session.token, { ...cookieOptions, maxAge: 15 * 60 * 1000 }); // 15 minutes
      response.cookie('refresh_token', session.refreshToken, cookieOptions);

      // Prepare response data
      const responseData = {
        session_id: session.id,
        expires_in: 15 * 60, // 15 minutes in seconds
        user: {
          uuid: user.uuid,
          email: user.email,
          role: user.role,
          is_verified: user.is_verified,
          is_active: user.is_active,
          last_login_at: user.last_login_at?.toISOString()
        }
      };

      // Include profile information if available
      if (user.profile) {
        (responseData as any).profile = {
          uuid: user.profile.uuid,
          tags: user.profile.tags
        };
      }

      // Log successful login
      await this.auditService.logLoginSuccess(
        user.uuid,
        user.email,
        ipAddress,
        userAgent,
        session.id
      );

      this.logger.log('User logged in successfully', { userId: user.uuid, email: user.email });

      return ApiResponseDto.success(responseData, 'Login successful');
    } catch (error) {
      this.logger.error('Login failed', {
        email: loginDto.email,
        error: error.message,
        ipAddress: req?.headers['x-forwarded-for']?.toString() || req?.socket?.remoteAddress || 'unknown'
      });
      throw error;
    }
  }

  /**
   * Refresh JWT access token using refresh token
   * 
   * Generates a new access token using a valid refresh token.
   * Implements token rotation for enhanced security.
   * 
   * Process:
   * 1. Validates refresh token signature and expiration
   * 2. Verifies user exists and is active
   * 3. Checks stored refresh token matches
   * 4. Generates new access and refresh tokens
   * 5. Updates stored refresh token
   * 6. Sets new secure httpOnly cookies
   * 
   * Security Features:
   * - Token signature validation
   * - Token expiration checking
   * - Token rotation for security
   * - Database token validation
   * - httpOnly cookie storage
   * 
   * @param refreshToken - The refresh token to validate
   * @param response - Express response object for cookie setting
   * @returns Promise with new JWT tokens
   * 
   * @throws UnauthorizedException if refresh token is invalid or expired
   * @throws UnauthorizedException if user account is deactivated
   * @throws Error if token refresh fails
   */
  async refreshToken(refreshToken: string, response: Response): Promise<ApiResponseDto<any>> {
    try {
      // Verify the refresh token signature and expiration
      const payload = this.jwtService.verify(refreshToken);
      
      // Extract session ID from token
      const sessionId = payload.sessionId;
      if (!sessionId) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Refresh session using SessionService
      const session = await this.sessionService.refreshSession(sessionId, refreshToken);
      if (!session) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      // Find user by UUID from token
      const user = await this.userRepository.findOne({
        where: { uuid: payload.sub },
        relations: ['profile']
      });

      if (!user) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Check if user account is active
      if (!user.is_active) {
        throw new UnauthorizedException('Account is deactivated');
      }

      // Set secure httpOnly cookies
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        sameSite: 'strict' as const,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/'
      };

      // Set access token cookie (shorter expiration)
      response.cookie('access_token', session.token, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      // Set refresh token cookie (longer expiration)
      response.cookie('refresh_token', session.refreshToken, cookieOptions);

      // Prepare response without tokens in body
      const responseData: any = {
        session_id: session.id,
        expires_in: 15 * 60, // 15 minutes in seconds
        user: {
          uuid: user.uuid,
          email: user.email,
          role: user.role,
          is_active: user.is_active,
          is_verified: user.is_verified,
          is_configured: user.is_configured,
          last_login_at: user.last_login_at?.toISOString()
        }
      };

      // Include profile information if available
      if (user.profile) {
        responseData.profile = {
          uuid: user.profile.uuid,
          tags: user.profile.tags
        };
      }

      this.logger.log('Token refreshed successfully', { userId: user.uuid });

      return ApiResponseDto.success(responseData, 'Token refreshed successfully');
    } catch (error) {
      this.logger.error('Token refresh failed', error);
      throw error;
    }
  }

  /**
   * Logout user and clear all authentication data
   * 
   * Performs a complete logout by removing all stored authentication
   * data including cookies and server-side session.
   * 
   * @param response - Express response object for cookie clearing
   * @param sessionId - Optional session ID to invalidate
   * @returns Promise with logout confirmation
   * 
   * @example
   * await this.logout(res, sessionId);
   * // All auth data cleared, cookies removed, session invalidated
   * 
   * Logout process:
   * - Removes access token cookie
   * - Removes refresh token cookie
   * - Invalidates server-side session
   * - Logs logout event
   */
  async logout(response: Response, sessionId?: string): Promise<ApiResponseDto<null>> {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict' as const,
      path: '/',
    };
    response.clearCookie('access_token', cookieOptions);
    response.clearCookie('refresh_token', cookieOptions);
    // Forza la rimozione anche senza opzioni (fallback)
    response.clearCookie('access_token');
    response.clearCookie('refresh_token');

    if (sessionId) {
      await this.sessionService.invalidateSession(sessionId, 'LOGOUT');

    } else {

    }

    this.logger.log('User logged out successfully');
    return ApiResponseDto.success(null, 'Logout successful');
  }

  /**
   * Check authentication status
   * 
   * Verifies if the current user is authenticated by checking
   * the JWT token from cookies.
   * 
   * @param req - Request object with cookies
   * @returns Promise with authentication status
   */
  async checkAuthStatus(req: Request): Promise<ApiResponseDto<any>> {
    try {
      const accessToken = req.cookies?.access_token;
      
      if (!accessToken) {
        return ApiResponseDto.success({ authenticated: false }, 'Not authenticated');
      }

      // Verify the token
      const payload = this.jwtService.verify(accessToken);
      
      // Check if user exists and is active
      const user = await this.userRepository.findOne({
        where: { uuid: payload.sub },
        relations: ['profile']
      });

      if (!user || !user.is_active) {
        return ApiResponseDto.success({ authenticated: false }, 'User not found or inactive');
      }

      // Return user data without sensitive information
      const userData = {
        uuid: user.uuid,
        email: user.email,
        role: user.role,
        is_active: user.is_active,
        is_verified: user.is_verified,
        is_configured: user.is_configured
      };

      if (user.profile) {
        userData['profile'] = {
          uuid: user.profile.uuid,
          tags: user.profile.tags
        };
      }

      return ApiResponseDto.success({ 
        authenticated: true, 
        user: userData 
      }, 'Authenticated');

    } catch (error) {
      this.logger.error('Auth check failed', error);
      return ApiResponseDto.success({ authenticated: false }, 'Token invalid or expired');
    }
  }

  // ============================================================================
  // USER DATA METHODS
  // ============================================================================

  /**
   * Get current user data
   * 
   * Retrieves complete user information for the authenticated user.
   * Includes user account details and profile information.
   * 
   * @param userId - User UUID from JWT token
   * @returns Promise with user data and profile information
   * 
   * @throws UnauthorizedException if user not found
   * @throws Error if data retrieval fails
   */
  async getMe(userId: string): Promise<ApiResponseDto<any>> {
    try {

      
      const user = await this.userRepository.findOne({
        where: { uuid: userId },
        relations: ['profile']
      });

      if (!user) {
        this.logger.warn('User not found in getMe', { userId });
        throw new NotFoundException('User not found');
      }



      return {
        http_status_code: HttpStatus.OK,
        success: true,
        message: 'User data retrieved successfully',
        data: {
          user: {
            uuid: user.uuid,
            email: user.email,
            role: user.role,
            is_verified: user.is_verified,
            is_active: user.is_active,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login_at: user.last_login_at
          },
          profile: user.profile ? {
            uuid: user.profile.uuid,
            tags: user.profile.tags,
            metadata: user.profile.metadata,
            created_at: user.profile.created_at,
            updated_at: user.profile.updated_at
          } : null
        }
      };
    } catch (error) {
      this.logger.error('Get user data failed', error);
      throw error;
    }
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Extract client IP address from request object
   * 
   * Handles various proxy configurations and headers to determine
   * the actual client IP address for audit logging purposes.
   * 
   * Priority order:
   * 1. X-Forwarded-For header (first IP in list)
   * 2. X-Real-IP header
   * 3. Connection remote address
   * 4. Socket remote address
   * 
   * @param req - Express request object
   * @returns Client IP address or 'Unknown' if not available
   */
  private getClientIp(req?: any): string {
    if (!req) return 'Unknown';
    
    // Get IP from various headers and sources
    const forwardedFor = req.headers?.['x-forwarded-for'] as string;
    const realIp = req.headers?.['x-real-ip'] as string;
    const remoteAddr = req.connection?.remoteAddress || req.socket?.remoteAddress;
    
    // If we have X-Forwarded-For, take the first IP (original client)
    if (forwardedFor) {
      const ips = forwardedFor.split(',').map(ip => ip.trim());
      return ips[0];
    }
    
    // If we have X-Real-IP, use it
    if (realIp) {
      return realIp;
    }
    
    // If we have remote address, clean it up
    if (remoteAddr) {
      // Remove IPv6 prefix if present (::ffff:)
      return remoteAddr.replace(/^::ffff:/, '');
    }
    
    return 'Unknown';
  }

  /**
   * Extract user agent string from request object
   * 
   * @param req - Express request object
   * @returns User agent string or 'Unknown' if not available
   */
  private getUserAgent(req?: any): string {
    if (!req) return 'Unknown';
    return req.headers?.['user-agent'] || 'Unknown';
  }

  /**
   * Extract device information from request object
   * 
   * @param req - Express request object
   * @returns Device information string
   */
  private getDeviceInfo(req?: any): string {
    if (!req) return 'Unknown';

    const userAgent = req.headers?.['user-agent'] || 'Unknown';
    const device = this.detectDevice(userAgent);
    const os = this.detectOS(userAgent);
    const browser = this.detectBrowser(userAgent);

    return `${device} - ${os} - ${browser}`;
  }

  /**
   * Detect device type (mobile, tablet, desktop)
   * 
   * @param userAgent - User agent string
   * @returns Device type string
   */
  private detectDevice(userAgent: string): string {
    if (userAgent.includes('Mobile') || userAgent.includes('Android') || userAgent.includes('iPhone')) {
      return 'Mobile';
    }
    if (userAgent.includes('Tablet') || userAgent.includes('iPad')) {
      return 'Tablet';
    }
    return 'Desktop';
  }

  /**
   * Detect operating system
   * 
   * @param userAgent - User agent string
   * @returns Operating system string
   */
  private detectOS(userAgent: string): string {
    if (userAgent.includes('Windows')) {
      return 'Windows';
    }
    if (userAgent.includes('Mac OS X')) {
      return 'Mac OS X';
    }
    if (userAgent.includes('Linux')) {
      return 'Linux';
    }
    if (userAgent.includes('Android')) {
      return 'Android';
    }
    if (userAgent.includes('iOS')) {
      return 'iOS';
    }
    return 'Unknown';
  }

  /**
   * Detect browser
   * 
   * @param userAgent - User agent string
   * @returns Browser string
   */
  private detectBrowser(userAgent: string): string {
    if (userAgent.includes('Chrome')) {
      return 'Chrome';
    }
    if (userAgent.includes('Firefox')) {
      return 'Firefox';
    }
    if (userAgent.includes('Safari')) {
      return 'Safari';
    }
    if (userAgent.includes('Opera')) {
      return 'Opera';
    }
    if (userAgent.includes('Edge')) {
      return 'Edge';
    }
    return 'Unknown';
  }

  // ============================================================================
  // EMAIL VERIFICATION METHODS
  // ============================================================================

  /**
   * Verify user email address
   * 
   * Validates email verification token and marks user as verified.
   * Required for full account access and functionality.
   * 
   * Process:
   * 1. Validates verification token
   * 2. Checks token expiration
   * 3. Updates user verification status
   * 4. Clears verification token
   * 5. Logs verification event
   * 
   * @param verifyEmailDto - Email verification data
   * @param req - Express request object for IP tracking
   * @returns Promise with verification confirmation
   * 
   * @throws BadRequestException if token is invalid or expired
   * @throws Error if verification process fails
   */
  async verifyEmail(verifyEmailDto: VerifyEmailDto, req?: any): Promise<ApiResponseDto<null>> {
    try {
      // Find user by verification token
      const user = await this.userRepository.findOne({
        where: { verification_token: verifyEmailDto.token }
      });

      if (!user) {
        throw new BadRequestException('Invalid verification OTP code');
      }

      // Check if token is expired
      if (user.verification_expires && user.verification_expires < new Date()) {
        throw new BadRequestException('Verification OTP code has expired');
      }

      // Update user verification status and clear token
      user.is_verified = true;
      user.verification_token = null;
      user.verification_expires = null;
      await this.userRepository.save(user);

      // Log email verification with IP and user agent
      const clientIp = this.getClientIp(req);
      const userAgent = this.getUserAgent(req);
      await this.auditService.logEmailVerification(user.uuid, user.email, clientIp, userAgent);


      
      return ApiResponseDto.success(null, 'Email verified successfully');
    } catch (error) {
      this.logger.error('Email verification failed', error);
      throw error;
    }
  }

  /**
   * Resend verification email
   * 
   * Generates and sends a new verification email to unverified users.
   * Useful when original verification email expires or is lost.
   * 
   * Process:
   * 1. Validates user email and verification status
   * 2. Generates new verification token
   * 3. Updates user with new token
   * 4. Sends verification email
   * 
   * @param email - User email address
   * @returns Promise with resend confirmation
   * 
   * @throws BadRequestException if email is already verified
   * @throws BadRequestException if email sending fails
   * @throws Error if resend process fails
   */
  async resendVerificationEmail(email: string): Promise<ApiResponseDto<null>> {
    try {
      const user = await this.userRepository.findOne({
        where: { email }
      });

      if (!user) {
        // Don't reveal if user exists or not for security
        this.logger.log('Verification resend requested for non-existent email', { email });
        return ApiResponseDto.success(null, 'If the email exists, a verification link has been sent');
      }

      if (user.is_verified) {
        throw new BadRequestException('Email is already verified');
      }

      // Generate new verification token (6-digit OTP)
      const verificationToken = this.generateSecureToken();
      const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Update user with new verification token
      user.verification_token = verificationToken;
      user.verification_expires = verificationExpiry;
      await this.userRepository.save(user);

      // Send verification email
      try {
        await this.mailService.sendVerificationEmail(user.email, verificationToken);
  
      } catch (emailError) {
        this.logger.error('Failed to resend verification email', { email: user.email, error: emailError });
      }



      return ApiResponseDto.success(null, 'Verification email sent successfully');
    } catch (error) {
      this.logger.error('Resend verification email failed', error);
      throw error;
    }
  }

  // ============================================================================
  // PASSWORD RECOVERY METHODS
  // ============================================================================

  /**
   * Send password reset link
   * 
   * Initiates password reset process by sending OTP to user's email.
   * Provides security by not revealing if email exists.
   * 
   * Process:
   * 1. Validates email address
   * 2. Generates reset OTP
   * 3. Sends reset email
   * 4. Stores reset token with expiration
   * 
   * Security Features:
   * - Doesn't reveal if email exists
   * - OTP expiration (24 hours)
   * - Secure token generation
   * 
   * @param forgotPasswordDto - Email for password reset
   * @returns Promise with reset request confirmation
   * 
   * @throws Error if reset process fails
   */
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<ApiResponseDto<any>> {
    try {
      const user = await this.userRepository.findOne({
        where: { email: forgotPasswordDto.email }
      });

      if (!user) {
        // Don't reveal if user exists or not for security
        this.logger.log('Password reset requested for non-existent email', { email: forgotPasswordDto.email });
        return ApiResponseDto.success(null, 'If the email exists, a password reset link has been sent');
      }

      // Generate reset token (6-digit OTP)
      const resetToken = this.generateSecureToken();
      const resetTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Update user with reset token
      user.reset_token = resetToken;
      user.reset_token_expiry = resetTokenExpiry;
      await this.userRepository.save(user);

      // Send reset email (non-blocking)
      try {
        await this.mailService.sendPasswordResetEmail(user.email, resetToken);
  
      } catch (emailError) {
        this.logger.error('Failed to send password reset email', { email: user.email, error: emailError });
        // Don't fail the request if email fails, just log it
      }



      return ApiResponseDto.success(null, 'If the email exists, a password reset link has been sent');
    } catch (error) {
      this.logger.error('Forgot password failed', error);
      throw error;
    }
  }

  /**
   * Reset password using OTP
   * 
   * Validates OTP and updates user password with new secure hash.
   * Requires valid OTP from forgot password request.
   * 
   * Process:
   * 1. Validates OTP token
   * 2. Checks token expiration
   * 3. Hashes new password securely
   * 4. Updates user password
   * 5. Clears reset token
   * 6. Logs password change events
   * 
   * Security Features:
   * - OTP validation and expiration checking
   * - Password hashing with bcrypt (12 rounds)
   * - Comprehensive audit logging
   * - IP and user agent tracking
   * 
   * @param resetPasswordDto - OTP and new password data
   * @param req - Express request object for IP tracking
   * @returns Promise with password reset confirmation
   * 
   * @throws BadRequestException if OTP is invalid or expired
   * @throws Error if reset process fails
   */
  async resetPassword(resetPasswordDto: ResetPasswordDto, req?: any): Promise<ApiResponseDto<null>> {
    try {
      // Find user by reset token (OTP)
      const user = await this.userRepository.findOne({
        where: { reset_token: resetPasswordDto.otp }
      });

      if (!user) {
        throw new BadRequestException('Invalid OTP code');
      }

      // Check if token is expired
      if (user.reset_token_expiry && user.reset_token_expiry < new Date()) {
        throw new BadRequestException('OTP code has expired');
      }

      // Hash new password with bcrypt (12 rounds for security)
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(resetPasswordDto.password, saltRounds);

      // Update user password and clear reset token
      user.password_hash = passwordHash;
      user.reset_token = null;
      user.reset_token_expiry = null;
      await this.userRepository.save(user);

      // Extract IP and User Agent for audit logging
      const clientIp = this.getClientIp(req);
      const userAgent = this.getUserAgent(req);

      // Log password reset and change events
      await this.auditService.logPasswordReset(user.uuid, user.email, clientIp, userAgent);
      await this.auditService.logPasswordChange(user.uuid, user.email, clientIp, userAgent);


      
      return ApiResponseDto.success(null, 'Password reset successfully');
    } catch (error) {
      this.logger.error('Password reset failed', error);
      throw error;
    }
  }

  // ============================================================================
  // SECURITY UTILITY METHODS
  // ============================================================================

  /**
   * Generate a secure 6-digit OTP (One-Time Password)
   * 
   * Creates a random 6-digit numeric code for verification and reset purposes.
   * Used for email verification and password reset functionality.
   * 
   * @returns 6-digit numeric string
   */
  private generateSecureToken(): string {
    // Generate a random 6-digit number (100000 to 999999)
    const otp = Math.floor(100000 + Math.random() * 900000);
    return otp.toString();
  }
}