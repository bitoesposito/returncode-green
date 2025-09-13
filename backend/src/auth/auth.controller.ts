import { 
  Body, 
  Controller, 
  Post, 
  Get, 
  HttpCode, 
  HttpStatus, 
  UseGuards, 
  Req,
  Res
} from '@nestjs/common';
import { Request, Response } from 'express';

// Local imports
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CookieAuthGuard } from './guards/cookie-auth.guard';
import { 
  LoginDto, 
  RegisterDto, 
  ForgotPasswordDto, 
  ResetPasswordDto, 
  VerifyEmailDto, 
  ResendVerificationDto, 
  RefreshTokenDto 
} from './auth.dto';
import { ApiResponseDto } from '../common/common.interface';
import { AuthService } from './auth.service';

/**
 * Interface for authenticated request
 * 
 * Extends the Express Request interface to include user information
 * that is added by the JWT authentication guard.
 */
interface AuthenticatedRequest extends Request {
  user: {
    /** Unique identifier for the authenticated user */
    uuid: string;
    /** Email address of the authenticated user */
    email: string;
    /** Role of the authenticated user */
    role: string;
    /** Session ID for logout */
    sessionId?: string;
  };
}

/**
 * Auth Controller
 * 
 * Handles all authentication-related endpoints for user registration,
 * login, verification, and password recovery operations.
 * 
 * Features:
 * - User registration with email verification
 * - Secure login with JWT token generation
 * - Token refresh functionality
 * - Email verification system
 * - Password reset via OTP
 * - User profile retrieval
 * 
 * Security:
 * - Password validation and hashing
 * - JWT token management
 * - Rate limiting (implemented in service)
 * - Audit logging for security events
 * 
 * Endpoints:
 * - POST /auth/register - User registration
 * - POST /auth/login - User authentication
 * - POST /auth/refresh - Token refresh
 * - GET /auth/me - Current user data
 * - POST /auth/verify - Email verification
 * - POST /auth/forgot-password - Password reset request
 * - POST /auth/reset-password - Password reset
 * - POST /auth/resend-verification - Resend verification email
 */
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService
  ) {}

  // ============================================================================
  // REGISTRATION AND AUTHENTICATION ENDPOINTS
  // ============================================================================

  /**
   * Register a new user account
   * 
   * Creates a new user account with email verification.
   * Sends a verification email to the provided email address.
   * 
   * Process:
   * 1. Validates registration data
   * 2. Checks for existing user
   * 3. Hashes password securely
   * 4. Creates user profile
   * 5. Sends verification email
   * 6. Logs registration event
   * 
   * @param registerDto - User registration data (email, password)
   * @returns Promise with registration confirmation
   * 
   * @example
   * POST /auth/register
   * {
   *   "email": "user@example.com",
   *   "password": "SecurePass123!"
   * }
   */
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto): Promise<ApiResponseDto<any>> {
    return this.authService.register(registerDto);
  }

  /**
   * Authenticate user and generate JWT tokens
   * 
   * Validates user credentials and generates access and refresh tokens.
   * Supports "remember me" functionality for extended sessions.
   * 
   * Process:
   * 1. Validates login credentials
   * 2. Checks user account status
   * 3. Verifies password hash
   * 4. Generates JWT tokens
   * 5. Updates last login timestamp
   * 6. Logs successful login
   * 
   * @param loginDto - User login credentials
   * @param req - Express request object for IP tracking
   * @returns Promise with JWT tokens and user data
   * 
   * @example
   * POST /auth/login
   * {
   *   "email": "user@example.com",
   *   "password": "SecurePass123!",
   *   "rememberMe": false
   * }
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto, 
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<ApiResponseDto<any>> {
    return this.authService.login(loginDto, res, req);
  }

  /**
   * Refresh JWT access token
   * 
   * Generates a new access token using a valid refresh token.
   * Implements token rotation for enhanced security.
   * 
   * Process:
   * 1. Validates refresh token
   * 2. Checks user account status
   * 3. Generates new access token
   * 4. Rotates refresh token
   * 5. Updates stored tokens
   * 
   * @param refreshTokenDto - Refresh token data
   * @returns Promise with new JWT tokens
   * 
   * @example
   * POST /auth/refresh
   * {
   *   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * }
   */
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshToken(
    @Body() refreshTokenDto: RefreshTokenDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<ApiResponseDto<any>> {
    return this.authService.refreshToken(refreshTokenDto.refresh_token, res);
  }

  /**
   * Logout user and clear authentication data
   * 
   * Performs a complete logout by removing all stored authentication
   * data including cookies and server-side session.
   * 
   * Process:
   * 1. Clears authentication cookies
   * 2. Invalidates server-side session
   * 3. Logs logout event
   * 
   * @param req - Authenticated request object with user data
   * @param res - Express response object for cookie clearing
   * @returns Promise with logout confirmation
   * 
   * @example
   * POST /auth/logout
   * Authorization: Bearer <jwt_token>
   */
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @UseGuards(CookieAuthGuard)
  async logout(
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) res: Response
  ): Promise<ApiResponseDto<null>> {
    // Extract session ID from user object (added by CookieAuthGuard)
    const sessionId = req.user?.sessionId;
    
    return this.authService.logout(res, sessionId);
  }

  // ============================================================================
  // USER DATA ENDPOINTS
  // ============================================================================

  /**
   * Get current authenticated user data
   * 
   * Retrieves complete user information for the authenticated user.
   * Requires valid JWT token in Authorization header.
   * 
   * @param req - Authenticated request object with user data
   * @returns Promise with user profile and account information
   * 
   * @example
   * GET /auth/me
   * Authorization: Bearer <jwt_token>
   */
  @Get('me')
  @UseGuards(CookieAuthGuard)
  async getMe(@Req() req: AuthenticatedRequest): Promise<ApiResponseDto<any>> {
    return this.authService.getMe(req.user.uuid);
  }

  /**
   * Check authentication status
   * 
   * Verifies if the current user is authenticated by checking
   * the JWT token from cookies.
   * 
   * @param req - Request object with cookies
   * @returns Promise with authentication status
   * 
   * @example
   * GET /auth/check
   */
  @Get('check')
  async checkAuth(@Req() req: Request): Promise<ApiResponseDto<any>> {
    return this.authService.checkAuthStatus(req);
  }

  // ============================================================================
  // EMAIL VERIFICATION ENDPOINTS
  // ============================================================================

  /**
   * Verify user email address
   * 
   * Validates email verification token and marks user as verified.
   * Required for full account access.
   * 
   * Process:
   * 1. Validates verification token
   * 2. Checks token expiration
   * 3. Updates user verification status
   * 4. Logs verification event
   * 
   * @param verifyEmailDto - Email verification data
   * @returns Promise with verification confirmation
   * 
   * @example
   * POST /auth/verify
   * {
   *   "token": "123456"
   * }
   */
  @Post('verify')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(
    @Body() verifyEmailDto: VerifyEmailDto
  ): Promise<ApiResponseDto<null>> {
    return this.authService.verifyEmail(verifyEmailDto);
  }

  /**
   * Resend email verification
   * 
   * Generates and sends a new verification email to unverified users.
   * Useful when original verification email expires or is lost.
   * 
   * Process:
   * 1. Validates user email
   * 2. Checks verification status
   * 3. Generates new verification token
   * 4. Sends verification email
   * 
   * @param resendVerificationDto - Email for verification resend
   * @returns Promise with resend confirmation
   * 
   * @example
   * POST /auth/resend-verification
   * {
   *   "email": "user@example.com"
   * }
   */
  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  async resendVerification(
    @Body() resendVerificationDto: ResendVerificationDto
  ): Promise<ApiResponseDto<null>> {
    return this.authService.resendVerificationEmail(resendVerificationDto.email);
  }

  // ============================================================================
  // PASSWORD RECOVERY ENDPOINTS
  // ============================================================================

  /**
   * Request password reset
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
   * @param forgotPasswordDto - Email for password reset
   * @returns Promise with reset request confirmation
   * 
   * @example
   * POST /auth/forgot-password
   * {
   *   "email": "user@example.com"
   * }
   */
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto
  ): Promise<ApiResponseDto<any>> {
    return this.authService.forgotPassword(forgotPasswordDto);
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
   * 3. Hashes new password
   * 4. Updates user password
   * 5. Clears reset token
   * 6. Logs password change
   * 
   * @param resetPasswordDto - OTP and new password data
   * @param req - Express request object for IP tracking
   * @returns Promise with password reset confirmation
   * 
   * @example
   * POST /auth/reset-password
   * {
   *   "otp": "123456",
   *   "password": "NewSecurePass123!"
   * }
   */
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto, 
    @Req() req: Request
  ): Promise<ApiResponseDto<null>> {
    return this.authService.resetPassword(resetPasswordDto, req);
  }
}