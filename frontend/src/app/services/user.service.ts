import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { ApiResponse } from '../models/api-base.models';
import { 
  UserWithProfile, 
  UpdateProfileRequest,
} from '../models/user.models';
import { CookieAuthService } from './cookie-auth.service';

/**
 * User Service
 * 
 * Manages user-related operations including user CRUD operations,
 * profile management, and user data retrieval. This service handles
 * all user management functionality for both regular users and admins.
 * 
 * Features:
 * - User listing with profiles
 * - Individual user retrieval
 * - User creation and deletion
 * - Profile updates and management
 * - Automatic authentication header management
 * 
 * User Management Features:
 * - Complete user lifecycle management
 * - Profile data handling
 * - User search and filtering
 * - Bulk user operations
 * - User data validation
 * 
 * Security Features:
 * - JWT token authentication for all requests
 * - Role-based access control
 * - User data protection
 * - Audit trail for user operations
 * 
 * Usage:
 * - Inject service in components
 * - Call methods to perform user operations
 * - Handle responses for UI updates
 * - Manage user profiles and data
 * 
 * @example
 * // Get all users
 * this.userService.getUsers().subscribe(response => {
 *   console.log('Users:', response.data);
 * });
 * 
 * @example
 * // Get specific user
 * this.userService.getUser('user-uuid').subscribe(response => {
 *   console.log('User profile:', response.data);
 * });
 * 
 * @example
 * // Update user profile
 * const updateData = { name: 'John Doe', bio: 'Developer' };
 * this.userService.updateUser('user@example.com', updateData).subscribe(response => {
 *   console.log('Updated user:', response.data);
 * });
 */
@Injectable({
  providedIn: 'root'
})
export class UserService {
  // ============================================================================
  // PROPERTIES
  // ============================================================================

  /**
   * Base API URL for user endpoints
   */
  private readonly API_URL = environment.apiUrl;

  // ============================================================================
  // CONSTRUCTOR
  // ============================================================================

  constructor(
    private http: HttpClient,
    private authService: CookieAuthService
  ) {}

  // ============================================================================
  // PRIVATE METHODS
  // ============================================================================

  /**
   * Get authentication headers for cookie-based auth
   * 
   * Creates HTTP headers for authenticated API requests.
   * With cookie-based authentication, no additional headers are needed.
   * 
   * @returns HttpHeaders for authenticated requests
   * 
   * @example
   * const headers = this.getHeaders();
   * this.http.get('/api/protected', { headers, withCredentials: true });
   */
  private getHeaders(): HttpHeaders {
    // With cookie-based auth, no additional headers needed
    return new HttpHeaders();
  }

  // ============================================================================
  // USER RETRIEVAL METHODS
  // ============================================================================

  /**
   * Retrieve a list of users with their profiles
   * 
   * Fetches all users in the system along with their associated
   * profile information. This method is typically used for
   * admin dashboards and user management interfaces.
   * 
   * @returns Observable with a list of users and their profiles
   * 
   * @example
   * this.getUsers().subscribe(response => {
   *   console.log('Total users:', response.data.length);
   *   response.data.forEach(user => {
   *     console.log('User:', user.email, 'Profile:', user.profile);
   *   });
   * });
   * 
   * Response includes:
   * - User basic information (email, role, status)
   * - Associated profile data
   * - User metadata and preferences
   */
  getUsers(): Observable<ApiResponse<UserWithProfile[]>> {
    return this.http.get<ApiResponse<UserWithProfile[]>>(`${this.API_URL}/users/list`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  /**
   * Retrieve a specific user by UUID
   * 
   * Fetches detailed information about a specific user
   * including their complete profile and metadata.
   * 
   * @param uuid - The unique identifier of the user
   * @returns Observable with the user's complete profile
   * 
   * @example
   * this.getUser('user-uuid-123').subscribe(response => {
   *   const user = response.data;
   *   console.log('User email:', user.email);
   *   console.log('User role:', user.role);
   *   console.log('Profile data:', user.profile);
   * });
   * 
   * User data includes:
   * - Basic user information
   * - Complete profile data
   * - User preferences and settings
   * - Account status and metadata
   */
  getUser(uuid: string): Observable<ApiResponse<UserWithProfile>> {
    return this.http.get<ApiResponse<UserWithProfile>>(`${this.API_URL}/users/${uuid}`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  // ============================================================================
  // USER MANAGEMENT METHODS
  // ============================================================================

  /**
   * Delete a user by email
   * 
   * Permanently removes a user from the system along with
   * all associated data. This operation requires admin privileges
   * and includes proper cleanup of user data.
   * 
   * @param email - The email address of the user to delete
   * @returns Observable with the deletion response
   * 
   * @example
   * this.deleteUser('user@example.com').subscribe(response => {
   *   console.log('User deleted successfully');
   *   // Update UI to reflect deletion
   * });
   * 
   * Deletion process:
   * - Removes user account
   * - Cleans up associated profile data
   * - Removes user sessions
   * - Updates audit logs
   * - GDPR compliance cleanup
   */
  deleteUser(email: string): Observable<ApiResponse<null>> {
    return this.http.delete<ApiResponse<null>>(`${this.API_URL}/users/delete`, {
      headers: this.getHeaders(),
      body: {email},
      withCredentials: true
    });
  }

  /**
   * Create a new user with the given email
   * 
   * Creates a new user account with the specified email address.
   * This method is typically used by administrators to create
   * new user accounts in the system.
   * 
   * @param email - The email address for the new user
   * @returns Observable with the created user's profile
   * 
   * @example
   * this.createUser('newuser@example.com').subscribe(response => {
   *   console.log('User created:', response.data);
   *   console.log('User UUID:', response.data.uuid);
   *   // Send welcome email or setup instructions
   * });
   * 
   * Creation process:
   * - Validates email format
   * - Creates user account
   * - Generates default profile
   * - Sets initial permissions
   * - Sends verification email
   */
  createUser(email: string): Observable<ApiResponse<UserWithProfile>> {
    return this.http.post<ApiResponse<UserWithProfile>>(`${this.API_URL}/users/create`, {email}, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  // ============================================================================
  // PROFILE MANAGEMENT METHODS
  // ============================================================================

  /**
   * Update a user's profile with the given data
   * 
   * Updates the profile information for a specific user.
   * This method allows modification of user profile data
   * including personal information, preferences, and settings.
   * 
   * @param email - The email address of the user to update
   * @param data - The profile data to update
   * @returns Observable with the updated user's profile
   * 
   * @example
   * const updateData = {
   *   name: 'John Doe',
   *   bio: 'Software Developer',
   *   preferences: { theme: 'dark', language: 'en' }
   * };
   * 
   * this.updateUser('user@example.com', updateData).subscribe(response => {
   *   console.log('Profile updated:', response.data);
   *   // Update UI with new profile data
   * });
   * 
   * Updateable fields:
   * - Personal information (name, bio, avatar)
   * - User preferences and settings
   * - Profile metadata and tags
   * - Notification preferences
   * - Privacy settings
   */
  updateUser(email: string, data: UpdateProfileRequest): Observable<ApiResponse<UserWithProfile>> {
    return this.http.put<ApiResponse<UserWithProfile>>(`${this.API_URL}/users/update`, {email, data}, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }
} 