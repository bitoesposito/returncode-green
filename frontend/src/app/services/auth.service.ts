import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { Observable, throwError } from 'rxjs';
import { ApiResponse } from '../models/api-base.models';
import { 
  LoginRequest, 
  LoginResponseData, 
  RegisterRequest, 
  RefreshTokenRequest, 
  ForgotPasswordRequest, 
  ResetPasswordRequest, 
  VerifyEmailRequest, 
  ResendVerificationRequest,
  UserData,
  LoginApiResponse,
  RegisterApiResponse,
  RefreshTokenApiResponse,
  ForgotPasswordApiResponse,
  ResetPasswordApiResponse,
  VerifyEmailApiResponse,
  ResendVerificationApiResponse,
  GetMeApiResponse
} from '../models/auth.models';
import { map, catchError, of } from 'rxjs';

/**
 * Authentication Service
 * 
 * Manages all authentication-related operations including user registration,
 * login, logout, password recovery, email verification, and token management.
 * This service handles the complete authentication lifecycle for the application.
 * 
 * Features:
 * - User registration and login
 * - Email verification and resend
 * - Password recovery and reset
 * - JWT token management
 * - Refresh token handling
 * - Remember me functionality
 * - Current user data retrieval
 * 
 * Authentication Flow:
 * - Registration with email verification
 * - Login with JWT token generation
 * - Token refresh for session maintenance
 * - Password recovery via email OTP
 * - Secure logout with token cleanup
 * 
 * Security Features:
 * - JWT token-based authentication
 * - Refresh token for session management
 * - Secure token storage (localStorage/sessionStorage)
 * - Remember me functionality
 * - Password reset with OTP verification
 * - Email verification for account activation
 * 
 * Token Management:
 * - Automatic token storage based on remember me setting
 * - Token retrieval from appropriate storage
 * - Secure token cleanup on logout
 * - Refresh token handling for session persistence
 * 
 * Usage:
 * - Inject service in components and guards
 * - Call authentication methods for user operations
 * - Handle responses for UI updates
 * - Manage user sessions and tokens
 * 
 * @example
 * // User registration
 * const registrationData = { email: 'user@example.com', password: 'password123' };
 * this.authService.register(registrationData).subscribe(response => {
 *   console.log('Registration successful:', response.message);
 * });
 * 
 * @example
 * // User login
 * const credentials = { email: 'user@example.com', password: 'password123' };
 * this.authService.login(credentials).subscribe(response => {
 *   this.authService.setToken(response.data.access_token);
 *   this.authService.setRefreshToken(response.data.refresh_token);
 * });
 * 
 * @example
 * // Check authentication status
 * if (this.authService.isAuthenticated()) {
 *   // User is logged in
 *   this.authService.getCurrentUser().subscribe(user => {
 *     console.log('Current user:', user.data);
 *   });
 * }
 */
@Injectable({
  providedIn: 'root'
})
export class AuthService {
  // ============================================================================
  // PROPERTIES
  // ============================================================================

  /**
   * Base API URL for authentication endpoints
   */
  private readonly API_URL = environment.apiUrl;

  // ============================================================================
  // CONSTRUCTOR
  // ============================================================================

  constructor(private http: HttpClient) {}

  // ============================================================================
  // USER REGISTRATION METHODS
  // ============================================================================

  /**
   * Register a new user account
   * 
   * Creates a new user account with the provided registration data.
   * The user will receive a verification email to activate their account.
   * 
   * @param registrationData - Registration data including email, password and optional display name
   * @returns Observable with registration response
   * 
   * @example
   * const registrationData = {
   *   email: 'user@example.com',
   *   password: 'SecurePassword123!',
   *   display_name: 'John Doe'
   * };
   * 
   * this.register(registrationData).subscribe(response => {
   *   console.log('Registration successful:', response.message);
   *   // Show verification email sent message
   * });
   * 
   * Registration process:
   * - Validates email format and password strength
   * - Creates user account with hashed password
   * - Sends verification email
   * - Returns success response with instructions
   */
  register(registrationData: RegisterRequest): Observable<RegisterApiResponse> {
    return this.http.post<RegisterApiResponse>(`${this.API_URL}/auth/register`, registrationData);
  }

  // ============================================================================
  // USER AUTHENTICATION METHODS
  // ============================================================================

  /**
   * Authenticate user with email and password
   * 
   * Performs user authentication and returns JWT tokens for session management.
   * The response includes access token, refresh token, and user data.
   * 
   * @param credentials - Login credentials (email and password)
   * @returns Observable with login response containing JWT token and user data
   * 
   * @example
   * const credentials = {
   *   email: 'user@example.com',
   *   password: 'SecurePassword123!'
   * };
   * 
   * this.login(credentials).subscribe(response => {
   *   // Store tokens
   *   this.setToken(response.data.access_token);
   *   this.setRefreshToken(response.data.refresh_token);
   *   
   *   // Navigate to dashboard
   *   // this.router.navigate(['/dashboard']); // Assuming router is available
   * });
   * 
   * Authentication process:
   * - Validates user credentials
   * - Checks account verification status
   * - Generates JWT access and refresh tokens
   * - Returns user data and tokens
   * - Updates last login timestamp
   */
  login(credentials: LoginRequest): Observable<LoginApiResponse> {
    return this.http.post<LoginApiResponse>(`${this.API_URL}/auth/login`, credentials);
  }

  /**
   * Get current user profile data
   * 
   * Retrieves the profile data for the currently authenticated user.
   * This method requires a valid JWT token in the request headers.
   * 
   * @returns Observable with current user profile data
   * 
   * @example
   * this.getCurrentUser().subscribe(response => {
   *   const user = response.data;
   *   console.log('User email:', user.email);
   *   console.log('User role:', user.role);
   *   console.log('Profile data:', user.profile);
   * });
   * 
   * User data includes:
   * - Basic user information (email, role, status)
   * - Profile data and preferences
   * - Account metadata and settings
   * - Verification and configuration status
   */
  getCurrentUser(): Observable<GetMeApiResponse> {
    return this.http.get<GetMeApiResponse>(`${this.API_URL}/auth/me`);
  }

  /**
   * Force refresh user data from server
   * 
   * Forces a fresh request to get current user data from the server.
   * This bypasses any cached data and ensures we have the latest information.
   * 
   * @returns Observable with fresh user profile and account information
   */
  forceRefreshUserData(): Observable<GetMeApiResponse> {
    return this.http.get<GetMeApiResponse>(`${this.API_URL}/auth/me`);
  }

  // ============================================================================
  // EMAIL VERIFICATION METHODS
  // ============================================================================

  /**
   * Verify email address with verification token
   * 
   * Verifies the user's email address using the token sent via email
   * during registration. This activates the user account.
   * 
   * @param data - Verification token from email
   * @returns Observable with verification response
   * 
   * @example
   * const verificationData = { token: 'verification-token-123' };
   * this.verifyEmail(verificationData).subscribe(response => {
   *   console.log('Email verified:', response.message);
   *   // Redirect to login or dashboard
   * });
   * 
   * Verification process:
   * - Validates verification token
   * - Updates user verification status
   * - Activates user account
   * - Returns success confirmation
   */
  verifyEmail(data: VerifyEmailRequest): Observable<VerifyEmailApiResponse> {
    return this.http.post<VerifyEmailApiResponse>(`${this.API_URL}/auth/verify`, data);
  }

  /**
   * Resend verification email
   * 
   * Sends a new verification email to the user's email address.
   * This is useful if the original verification email expired or was lost.
   * 
   * @param data - Email address for resending verification
   * @returns Observable with resend response
   * 
   * @example
   * const resendData = { email: 'user@example.com' };
   * this.resendVerification(resendData).subscribe(response => {
   *   console.log('Verification email resent:', response.message);
   *   // Show confirmation message to user
   * });
   * 
   * Resend process:
   * - Validates email address
   * - Generates new verification token
   * - Sends verification email
   * - Returns success confirmation
   */
  resendVerification(data: ResendVerificationRequest): Observable<ResendVerificationApiResponse> {
    return this.http.post<ResendVerificationApiResponse>(`${this.API_URL}/auth/resend-verification`, data);
  }

  // ============================================================================
  // PASSWORD RECOVERY METHODS
  // ============================================================================

  /**
   * Initiate password recovery process
   * 
   * Sends a password reset email with OTP to the user's email address.
   * This is the first step in the password recovery process.
   * 
   * @param data - Forgot password data containing email address
   * @returns Observable with recovery response
   * 
   * @example
   * const forgotData = { email: 'user@example.com' };
   * this.forgotPassword(forgotData).subscribe(response => {
   *   console.log('Password reset email sent:', response.message);
   *   // Show confirmation message to user
   * });
   * 
   * Recovery process:
   * - Validates email address
   * - Generates OTP for password reset
   * - Sends reset email with OTP
   * - Returns success confirmation
   */
  forgotPassword(data: ForgotPasswordRequest): Observable<ForgotPasswordApiResponse> {
    return this.http.post<ForgotPasswordApiResponse>(`${this.API_URL}/auth/forgot-password`, data);
  }

  /**
   * Reset password using OTP
   * 
   * Resets the user's password using the OTP received via email.
   * This is the second step in the password recovery process.
   * 
   * @param data - Reset password data containing OTP and new password
   * @returns Observable with reset response
   * 
   * @example
   * const resetData = {
   *   email: 'user@example.com',
   *   otp: '123456',
   *   new_password: 'NewSecurePassword123!'
   * };
   * 
   * this.resetPassword(resetData).subscribe(response => {
   *   console.log('Password reset successful:', response.message);
   *   // Redirect to login page
   * });
   * 
   * Reset process:
   * - Validates OTP and email combination
   * - Checks password strength requirements
   * - Updates user password with new hash
   * - Invalidates old sessions
   * - Returns success confirmation
   */
  resetPassword(data: ResetPasswordRequest): Observable<ResetPasswordApiResponse> {
    return this.http.post<ResetPasswordApiResponse>(`${this.API_URL}/auth/reset-password`, data);
  }

  // ============================================================================
  // TOKEN MANAGEMENT METHODS
  // ============================================================================

  /**
   * Store JWT access token based on remember me setting
   * 
   * Stores the JWT access token in either localStorage (remember me enabled)
   * or sessionStorage (remember me disabled) for session persistence.
   * 
   * @param token - JWT access token to store
   * 
   * @example
   * this.setToken('jwt-access-token-123');
   * // Token stored in localStorage if remember_me is true, otherwise in sessionStorage
   */
  setToken(token: string): void {
    const rememberMe = localStorage.getItem('remember_me') === 'true';
    if (rememberMe) {
      localStorage.setItem('access_token', token);
    } else {
      sessionStorage.setItem('access_token', token);
    }
  }

  /**
   * Store refresh token based on remember me setting
   * 
   * Stores the refresh token in either localStorage (remember me enabled)
   * or sessionStorage (remember me disabled) for token renewal.
   * 
   * @param refreshToken - Refresh token to store
   * 
   * @example
   * this.setRefreshToken('refresh-token-123');
   * // Refresh token stored in localStorage if remember_me is true, otherwise in sessionStorage
   */
  setRefreshToken(refreshToken: string): void {
    const rememberMe = localStorage.getItem('remember_me') === 'true';
    if (rememberMe) {
      localStorage.setItem('refresh_token', refreshToken);
    } else {
      sessionStorage.setItem('refresh_token', refreshToken);
    }
  }

  /**
   * Retrieve stored JWT access token
   * 
   * Retrieves the JWT access token from storage, checking localStorage first
   * (for remember me) then sessionStorage (for session-only storage).
   * 
   * @returns The stored JWT access token or null if not found
   * 
   * @example
   * const token = this.getToken();
   * if (token) {
   *   // Use token for authenticated requests
   *   // this.http.get('/api/protected', { headers: { Authorization: `Bearer ${token}` } }); // Assuming http is available
   * }
   */
  getToken(): string | null {
    // Check localStorage first (remember me), then sessionStorage
    return localStorage.getItem('access_token') || sessionStorage.getItem('access_token');
  }

  /**
   * Retrieve stored refresh token
   * 
   * Retrieves the refresh token from storage, checking localStorage first
   * (for remember me) then sessionStorage (for session-only storage).
   * 
   * @returns The stored refresh token or null if not found
   * 
   * @example
   * const refreshToken = this.getRefreshToken();
   * if (refreshToken) {
   *   // Use refresh token to get new access token
   *   this.refreshToken().subscribe(response => {
   *     this.setToken(response.data.access_token);
   *   });
   * }
   */
  getRefreshToken(): string | null {
    // Check localStorage first (remember me), then sessionStorage
    return localStorage.getItem('refresh_token') || sessionStorage.getItem('refresh_token');
  }

  /**
   * Remove stored JWT access token
   * 
   * Removes the JWT access token from both localStorage and sessionStorage
   * to ensure complete cleanup regardless of storage location.
   * 
   * @example
   * this.removeToken();
   * // Access token removed from both storage locations
   */
  removeToken(): void {
    localStorage.removeItem('access_token');
    sessionStorage.removeItem('access_token');
  }

  /**
   * Remove stored refresh token
   * 
   * Removes the refresh token from both localStorage and sessionStorage
   * to ensure complete cleanup regardless of storage location.
   * 
   * @example
   * this.removeRefreshToken();
   * // Refresh token removed from both storage locations
   */
  removeRefreshToken(): void {
    localStorage.removeItem('refresh_token');
    sessionStorage.removeItem('refresh_token');
  }

  /**
   * Refresh access token using refresh token
   * 
   * Uses the stored refresh token to obtain a new access token
   * when the current access token expires.
   * 
   * @returns Observable with new access and refresh tokens
   * 
   * @example
   * this.refreshToken().subscribe({
   *   next: (response) => {
   *     this.setToken(response.data.access_token);
   *     this.setRefreshToken(response.data.refresh_token);
   *     // Continue with original request
   *   },
   *   error: (error) => {
   *     // Refresh failed, redirect to login
   *     this.logout();
   *     // this.router.navigate(['/login']); // Assuming router is available
   *   }
   * });
   * 
   * Refresh process:
   * - Validates refresh token
   * - Generates new access and refresh tokens
   * - Invalidates old refresh token
   * - Returns new token pair
   */
  refreshToken(): Observable<RefreshTokenApiResponse> {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      return throwError(() => new Error('No refresh token available'));
    }
    return this.http.post<RefreshTokenApiResponse>(`${this.API_URL}/auth/refresh`, { refresh_token: refreshToken });
  }

  // ============================================================================
  // SESSION MANAGEMENT METHODS
  // ============================================================================

  /**
   * Logout user and clear all authentication data
   * 
   * Performs a complete logout by removing all stored authentication
   * data including tokens, user data, and remember me setting.
   * 
   * @example
   * this.logout();
   * // All auth data cleared, redirect to login
   * // this.router.navigate(['/login']); // Assuming router is available
   * 
   * Logout process:
   * - Removes access token from storage
   * - Removes refresh token from storage
   * - Removes remember me setting
   * - Removes user data from storage
   * - Clears any other auth-related data
   */
  logout(): void {
    localStorage.removeItem('access_token');
    sessionStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    sessionStorage.removeItem('refresh_token');
    localStorage.removeItem('remember_me');
    // Remove any other auth-related data that might be stored
    localStorage.removeItem('user_data');
  }

  /**
   * Force logout without server call
   * 
   * Immediately clears all authentication data without calling the server.
   * Useful for client-side logout when server is unavailable.
   */
  forceLogout(): void {
    this.logout();
  }

  /**
   * Check if current user is admin
   * 
   * Verifies if the current authenticated user has admin role.
   * This method makes a server call to get fresh user data.
   * 
   * @returns Observable with boolean indicating if user is admin
   */
  isAdmin(): Observable<boolean> {
    return this.getCurrentUser().pipe(
      map(response => {
        if (response.success && response.data?.user?.role) {
          return response.data.user.role === 'admin';
        }
        return false;
      }),
      catchError(() => of(false))
    );
  }

  /**
   * Get current user role
   * 
   * Retrieves the role of the current authenticated user.
   * This method makes a server call to get fresh user data.
   * 
   * @returns Observable with user role or null if not authenticated
   */
  getUserRole(): Observable<string | null> {
    return this.getCurrentUser().pipe(
      map(response => {
        if (response.success && response.data?.user?.role) {
          return response.data.user.role;
        }
        return null;
      }),
      catchError(() => of(null))
    );
  }

  /**
   * Check if current user has specific role
   * 
   * Verifies if the current authenticated user has the specified role.
   * This method makes a server call to get fresh user data.
   * 
   * @param role - Role to check for
   * @returns Observable with boolean indicating if user has the role
   */
  hasRole(role: string): Observable<boolean> {
    return this.getCurrentUser().pipe(
      map(response => {
        if (response.success && response.data?.user?.role) {
          return response.data.user.role === role;
        }
        return false;
      }),
      catchError(() => of(false))
    );
  }

  /**
   * Check if user is currently authenticated
   * 
   * Determines if the user is authenticated by checking for the
   * presence of a valid JWT access token in storage.
   * 
   * @returns boolean indicating if user is authenticated
   * 
   * @example
   * if (this.isAuthenticated()) {
   *   // User is logged in, show protected content
   *   // this.showDashboard(); // Assuming showDashboard is available
   * } else {
   *   // User is not logged in, redirect to login
   *   // this.router.navigate(['/login']); // Assuming router is available
   * }
   * 
   * Note: This method only checks for token presence, not validity.
   * Token validity should be verified with the server for critical operations.
   */
  isAuthenticated(): boolean {
    return !!this.getToken();
  }
} 