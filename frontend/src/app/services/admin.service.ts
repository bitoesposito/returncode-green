import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { ApiResponse } from '../models/api-base.models';
import { 
  SystemMetricsResponse, 
  DetailedSystemMetricsResponse, 
  UserManagementResponse, 
  AuditLogsResponse,
  GetMetricsResponse,
  GetDetailedMetricsResponse,
  GetUserManagementResponse,
  GetAuditLogsResponse,
  DeleteUserResponse
} from '../models/admin.models';
import { CookieAuthService } from './cookie-auth.service';
import { tap, catchError } from 'rxjs/operators';

/**
 * Admin Service
 * 
 * Manages administrative operations including system metrics monitoring,
 * user management, audit logs, and administrative controls. This service
 * provides comprehensive admin functionality for system administration.
 * 
 * Features:
 * - System metrics and performance monitoring
 * - User management and administration
 * - Audit log retrieval and analysis
 * - User suspension and deletion
 * - Administrative data visualization
 * - Automatic authentication header management
 * 
 * Admin Features:
 * - Real-time system performance metrics
 * - Detailed system health monitoring
 * - User account management
 * - Security audit trail access
 * - Administrative action logging
 * - System-wide data analysis
 * 
 * Security Features:
 * - JWT token authentication for all requests
 * - Role-based access control (admin only)
 * - Audit trail for all admin actions
 * - Secure user management operations
 * - Administrative action validation
 * 
 * Usage:
 * - Inject service in admin components
 * - Call methods to perform admin operations
 * - Handle responses for admin dashboard
 * - Monitor system health and user activity
 * 
 * @example
 * // Get system metrics
 * this.adminService.getMetrics().subscribe(response => {
 *   console.log('System metrics:', response.data);
 * });
 * 
 * @example
 * // Get user management data
 * this.adminService.getUsers(1, 10, 'search').subscribe(response => {
 *   console.log('Users:', response.data);
 * });
 * 
 * @example
 * // Get audit logs
 * this.adminService.getAuditLogs(1, 50).subscribe(response => {
 *   console.log('Audit logs:', response.data);
 * });
 */
@Injectable({
  providedIn: 'root'
})
export class AdminService {
  // ============================================================================
  // PROPERTIES
  // ============================================================================

  /**
   * Base API URL for admin endpoints
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
  // SYSTEM METRICS METHODS
  // ============================================================================

  /**
   * Get system metrics and performance data
   * 
   * Retrieves high-level system metrics including performance indicators,
   * resource usage, and system health status for administrative monitoring.
   * 
   * @returns Observable with system metrics data
   * 
   * @example
   * this.getMetrics().subscribe(response => {
   *   const metrics = response.data;
   *   console.log('CPU Usage:', metrics.cpu_usage);
   *   console.log('Memory Usage:', metrics.memory_usage);
   *   console.log('Active Users:', metrics.active_users);
   *   console.log('System Status:', metrics.status);
   * });
   * 
   * Metrics include:
   * - CPU and memory usage
   * - Database performance
   * - Active user count
   * - System uptime
   * - Error rates and response times
   */
  getMetrics(): Observable<GetMetricsResponse> {
    return this.http.get<GetMetricsResponse>(`${this.API_URL}/admin/metrics`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  /**
   * Get detailed system metrics and analytics
   * 
   * Retrieves comprehensive system metrics including detailed performance
   * data, historical trends, and granular system analytics for deep
   * administrative analysis.
   * 
   * @returns Observable with detailed system metrics data
   * 
   * @example
   * this.getDetailedMetrics().subscribe(response => {
   *   const detailedMetrics = response.data;
   *   console.log('Performance trends:', detailedMetrics.trends);
   *   console.log('Resource breakdown:', detailedMetrics.resources);
   *   console.log('Service health:', detailedMetrics.services);
   *   console.log('Historical data:', detailedMetrics.history);
   * });
   * 
   * Detailed metrics include:
   * - Performance trends over time
   * - Resource utilization breakdown
   * - Service-specific metrics
   * - Historical performance data
   * - Detailed error analysis
   * - Capacity planning data
   */
  getDetailedMetrics(): Observable<GetDetailedMetricsResponse> {
    return this.http.get<GetDetailedMetricsResponse>(`${this.API_URL}/admin/metrics/detailed`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  // ============================================================================
  // USER MANAGEMENT METHODS
  // ============================================================================

  /**
   * Get user management data with pagination and search
   * 
   * Retrieves user data for administrative management including
   * user profiles, account status, and activity information
   * with support for pagination and search functionality.
   * 
   * @param page - Page number for pagination (default: 1)
   * @param limit - Number of items per page (default: 10)
   * @param search - Optional search query for filtering users
   * @returns Observable with user management data
   * 
   * @example
   * // Get first page of users
   * this.getUsers(1, 10).subscribe(response => {
   *   console.log('Users:', response.data);
   *   console.log('Total users:', response.total);
   * });
   * 
   * @example
   * // Search for specific users
   * this.getUsers(1, 10, 'john@example.com').subscribe(response => {
   *   console.log('Search results:', response.data);
   * });
   * 
   * User data includes:
   * - Basic user information (email, role, status)
   * - Profile data and preferences
   * - Account activity and last login
   * - Verification and configuration status
   * - Administrative flags and metadata
   */
  getUsers(page: number = 1, limit: number = 10, search?: string): Observable<GetUserManagementResponse> {
    let url = `${this.API_URL}/admin/users?page=${page}&limit=${limit}`;
    if (search && search.trim() !== '') {
      url += `&search=${encodeURIComponent(search)}`;
    }
    return this.http.get<GetUserManagementResponse>(url, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  /**
   * Suspend a user account
   * 
   * Temporarily suspends a user account, preventing login and access
   * while preserving user data. This is a reversible administrative action.
   * 
   * @param uuid - Unique identifier of the user to suspend
   * @returns Observable with suspension response
   * 
   * @example
   * this.suspendUser('user-uuid-123').subscribe(response => {
   *   console.log('User suspended:', response.message);
   *   // Update UI to reflect suspension
   * });
   * 
   * Suspension process:
   * - Validates user exists and is not already suspended
   * - Updates user status to suspended
   * - Invalidates active sessions
   * - Logs administrative action
   * - Sends notification to user
   * - Preserves all user data
   */
  suspendUser(uuid: string): Observable<DeleteUserResponse> {
    return this.http.put<DeleteUserResponse>(`${this.API_URL}/admin/users/${uuid}/suspend`, {}, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  /**
   * Delete a user account permanently
   * 
   * Permanently removes a user account and all associated data from the system.
   * This is an irreversible administrative action that requires confirmation.
   * 
   * @param uuid - Unique identifier of the user to delete
   * @returns Observable with deletion response
   * 
   * @example
   * this.deleteUser('user-uuid-123').subscribe(response => {
   *   console.log('User deleted:', response.message);
   *   // Update UI to reflect deletion
   * });
   * 
   * Deletion process:
   * - Validates user exists and is not an admin
   * - Removes user account completely
   * - Cleans up all associated data
   * - Removes user sessions
   * - Logs administrative action
   * - GDPR compliance cleanup
   * - Irreversible operation
   */
  deleteUser(uuid: string): Observable<DeleteUserResponse> {
    return this.http.delete<DeleteUserResponse>(`${this.API_URL}/admin/users/${uuid}`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  // ============================================================================
  // AUDIT LOGS METHODS
  // ============================================================================

  /**
   * Get audit logs with pagination
   * 
   * Retrieves system audit logs for administrative review and security analysis.
   * These logs contain detailed records of all system activities and user actions.
   * 
   * @param page - Page number for pagination (default: 1)
   * @param limit - Number of items per page (default: 50)
   * @returns Observable with audit logs data
   * 
   * @example
   * this.getAuditLogs(1, 50).subscribe(response => {
   *   console.log('Audit logs:', response.data);
   *   console.log('Total logs:', response.total);
   *   
   *   response.data.forEach(log => {
   *     console.log('Action:', log.action);
   *     console.log('User:', log.user_email);
   *     console.log('Timestamp:', log.timestamp);
   *     console.log('Details:', log.details);
   *   });
   * });
   * 
   * Audit log data includes:
   * - User actions and system events
   * - Administrative operations
   * - Security-related activities
   * - Data access and modifications
   * - Error and exception logs
   * - Performance and system events
   * 
   * Error handling:
   * - Logs errors to console for debugging
   * - Re-throws errors for component handling
   * - Provides detailed error information
   */
  getAuditLogs(page: number = 1, limit: number = 50): Observable<GetAuditLogsResponse> {
    const url = `${this.API_URL}/admin/audit-logs?page=${page}&limit=${limit}`;
    
    return this.http.get<GetAuditLogsResponse>(url, {
      headers: this.getHeaders()
    }).pipe(
      tap((response: any) => {
        // Handle successful response if needed
        // Additional processing can be added here
      }),
      catchError((error: any) => {
        // Handle error appropriately
        console.error('Error fetching audit logs:', error);
        throw error;
      })
    );
  }
} 