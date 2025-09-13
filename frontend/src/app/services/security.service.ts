import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import {
  GetSecurityLogsResponse,
  GetSessionsResponse,
  DownloadDataApiResponse,
  DeleteAccountResponse
} from '../models/security.models';
import { CookieAuthService } from './cookie-auth.service';

/**
 * Security Service
 * 
 * Handles all security-related operations including user security logs,
 * session management, GDPR compliance features, and account deletion.
 * 
 * Features:
 * - Security logs retrieval with pagination
 * - Active sessions management
 * - GDPR data export functionality
 * - Account deletion with safety checks
 * - Automatic authentication header management
 * 
 * Security Features:
 * - JWT token authentication for all requests
 * - GDPR compliance for data export
 * - Secure account deletion process
 * - Session monitoring and management
 * 
 * GDPR Compliance:
 * - Data export functionality for user data
 * - Account deletion with proper cleanup
 * - Audit trail for security operations
 * 
 * Usage:
 * - Inject service in components
 * - Call methods to perform security operations
 * - Handle responses for UI updates
 * - Monitor security logs and sessions
 * 
 * @example
 * // Get security logs
 * this.securityService.getSecurityLogs(1, 10).subscribe(response => {
 *   console.log('Security logs:', response.data);
 * });
 * 
 * @example
 * // Download user data (GDPR)
 * this.securityService.downloadData().subscribe(response => {
 *   // Handle data download
 * });
 * 
 * @example
 * // Delete account
 * this.securityService.deleteAccount().subscribe(response => {
 *   // Handle account deletion
 * });
 */
@Injectable({
  providedIn: 'root'
})
export class SecurityService {
  // ============================================================================
  // PROPERTIES
  // ============================================================================

  /**
   * Base API URL for security endpoints
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
  // SECURITY LOGS METHODS
  // ============================================================================

  /**
   * Get user security logs with pagination
   * 
   * Retrieves security audit logs for the current user,
   * including login attempts, password changes, and security events.
   * 
   * @param page - Page number for pagination (default: 1)
   * @param limit - Number of items per page (default: 10)
   * @returns Observable with security logs and pagination metadata
   * 
   * @example
   * // Get first page with 10 items
   * this.getSecurityLogs(1, 10).subscribe(response => {
   *   console.log('Logs:', response.data);
   *   console.log('Total:', response.total);
   * });
   * 
   * @example
   * // Get second page with 20 items
   * this.getSecurityLogs(2, 20).subscribe(response => {
   *   // Handle paginated results
   * });
   */
  getSecurityLogs(page: number = 1, limit: number = 10): Observable<GetSecurityLogsResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString()
    });
    
    return this.http.get<GetSecurityLogsResponse>(`${this.API_URL}/security/logs?${params}`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  // ============================================================================
  // SESSION MANAGEMENT METHODS
  // ============================================================================

  /**
   * Get user active sessions
   * 
   * Retrieves all active sessions for the current user,
   * including device information and session metadata.
   * 
   * @returns Observable with user sessions list
   * 
   * @example
   * this.getSessions().subscribe(response => {
   *   console.log('Active sessions:', response.sessions);
   *   // Display sessions in UI for user review
   * });
   */
  getSessions(): Observable<GetSessionsResponse> {
    return this.http.get<GetSessionsResponse>(`${this.API_URL}/security/sessions`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  // ============================================================================
  // GDPR COMPLIANCE METHODS
  // ============================================================================

  /**
   * Download user data (GDPR compliance)
   * 
   * Initiates a GDPR-compliant data export for the current user.
   * This includes all user data, preferences, and activity logs
   * in a structured format for data portability.
   * 
   * @returns Observable with download data response
   * 
   * @example
   * this.downloadData().subscribe(response => {
   *   console.log('Download URL:', response.downloadUrl);
   *   // Provide download link to user
   * });
   * 
   * GDPR Features:
   * - Complete user data export
   * - Structured data format
   * - Secure download links
   * - Audit trail for data requests
   */
  downloadData(): Observable<DownloadDataApiResponse> {
    return this.http.get<DownloadDataApiResponse>(`${this.API_URL}/security/download-data`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  // ============================================================================
  // ACCOUNT MANAGEMENT METHODS
  // ============================================================================

  /**
   * Delete user account
   * 
   * Initiates the account deletion process for the current user.
   * This is a GDPR-compliant operation that permanently removes
   * all user data after safety checks and confirmation.
   * 
   * @returns Observable with deletion response
   * 
   * @example
   * this.deleteAccount().subscribe(response => {
   *   console.log('Account deletion initiated:', response.message);
   *   // Handle account deletion confirmation
   * });
   * 
   * Safety Features:
   * - Confirmation required before deletion
   * - Grace period for account recovery
   * - Complete data cleanup
   * - Audit trail for deletion requests
   */
  deleteAccount(): Observable<DeleteAccountResponse> {
    return this.http.delete<DeleteAccountResponse>(`${this.API_URL}/security/delete-account`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }
} 