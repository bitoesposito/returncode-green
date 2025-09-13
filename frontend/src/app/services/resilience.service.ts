import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import {
  GetSystemStatusResponse,
  CreateBackupResponse,
  ListBackupsResponse,
  RestoreBackupResponse,
  GetBackupStatusResponse
} from '../models/resilience.models';
import { CookieAuthService } from './cookie-auth.service';

/**
 * Resilience Service
 * 
 * Manages system resilience operations including health checks,
 * backup creation and restoration, and system status monitoring.
 * 
 * Features:
 * - System health monitoring
 * - Manual backup creation
 * - Backup listing with pagination
 * - System restoration from backups
 * - Backup automation status monitoring
 * - Automatic authentication header management
 * 
 * System Resilience Features:
 * - Real-time system status monitoring
 * - Automated backup scheduling
 * - Manual backup operations
 * - System recovery capabilities
 * - Backup integrity verification
 * 
 * Usage:
 * - Inject service in components
 * - Call methods to perform resilience operations
 * - Handle responses for UI updates
 * - Monitor system health and backup status
 * 
 * @example
 * // Check system status
 * this.resilienceService.getSystemStatus().subscribe(response => {
 *   console.log('System status:', response.status);
 * });
 * 
 * @example
 * // Create backup
 * this.resilienceService.createBackup().subscribe(response => {
 *   console.log('Backup created:', response.backupId);
 * });
 * 
 * @example
 * // List backups
 * this.resilienceService.listBackups(1, 10).subscribe(response => {
 *   console.log('Backups:', response.backups);
 * });
 */
@Injectable({
  providedIn: 'root'
})
export class ResilienceService {
  // ============================================================================
  // PROPERTIES
  // ============================================================================

  /**
   * Base API URL for resilience endpoints
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
  // SYSTEM STATUS METHODS
  // ============================================================================

  /**
   * Get system status (health check)
   * 
   * Retrieves the current system health status including
   * database connectivity, service availability, and system metrics.
   * 
   * @returns Observable with system status and health information
   * 
   * @example
   * this.getSystemStatus().subscribe(response => {
   *   console.log('System health:', response.status);
   *   console.log('Database:', response.database);
   *   console.log('Services:', response.services);
   * });
   * 
   * Health Check Features:
   * - Database connectivity status
   * - Service availability monitoring
   * - System resource metrics
   * - Response time measurements
   */
  getSystemStatus(): Observable<GetSystemStatusResponse> {
    return this.http.get<GetSystemStatusResponse>(`${this.API_URL}/resilience/status`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  // ============================================================================
  // BACKUP MANAGEMENT METHODS
  // ============================================================================

  /**
   * Create system backup
   * 
   * Initiates a manual system backup operation.
   * This creates a complete snapshot of the system state
   * including database, configuration, and user data.
   * 
   * @returns Observable with backup creation response
   * 
   * @example
   * this.createBackup().subscribe(response => {
   *   console.log('Backup ID:', response.backupId);
   *   console.log('Status:', response.status);
   *   // Monitor backup progress
   * });
   * 
   * Backup Features:
   * - Complete system snapshot
   * - Database backup with integrity checks
   * - Configuration backup
   * - User data backup
   * - Backup metadata storage
   */
  createBackup(): Observable<CreateBackupResponse> {
    return this.http.post<CreateBackupResponse>(`${this.API_URL}/resilience/backup`, {}, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  /**
   * List available backups with pagination
   * 
   * Retrieves a paginated list of available system backups
   * with metadata including creation date, size, and status.
   * 
   * @param page - Page number for pagination (1-based)
   * @param limit - Number of items per page
   * @returns Observable with backup list and pagination metadata
   * 
   * @example
   * // Get first page with 10 backups
   * this.listBackups(1, 10).subscribe(response => {
   *   console.log('Backups:', response.backups);
   *   console.log('Total:', response.total);
   * });
   * 
   * @example
   * // Get second page with 20 backups
   * this.listBackups(2, 20).subscribe(response => {
   *   // Handle paginated backup list
   * });
   */
  listBackups(page: number = 1, limit: number = 10): Observable<ListBackupsResponse> {
    return this.http.get<ListBackupsResponse>(`${this.API_URL}/resilience/backup?page=${page}&limit=${limit}`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  /**
   * Restore system from backup
   * 
   * Initiates a system restoration operation from a specified backup.
   * This operation restores the complete system state to the
   * point when the backup was created.
   * 
   * @param backupId - Unique identifier of the backup to restore from
   * @returns Observable with restore operation response
   * 
   * @example
   * this.restoreBackup('backup-123').subscribe(response => {
   *   console.log('Restore status:', response.status);
   *   console.log('Progress:', response.progress);
   *   // Monitor restoration progress
   * });
   * 
   * Restore Features:
   * - Complete system restoration
   * - Database restoration with integrity checks
   * - Configuration restoration
   * - User data restoration
   * - Progress monitoring
   * - Rollback capabilities
   */
  restoreBackup(backupId: string): Observable<RestoreBackupResponse> {
    return this.http.post<RestoreBackupResponse>(`${this.API_URL}/resilience/backup/${backupId}/restore`, {}, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }

  // ============================================================================
  // BACKUP AUTOMATION METHODS
  // ============================================================================

  /**
   * Get backup automation status
   * 
   * Retrieves the current status of automated backup operations
   * including schedule information, last backup time, and
   * automation configuration.
   * 
   * @returns Observable with backup automation status
   * 
   * @example
   * this.getBackupStatus().subscribe(response => {
   *   console.log('Automation enabled:', response.automationEnabled);
   *   console.log('Schedule:', response.schedule);
   *   console.log('Last backup:', response.lastBackup);
   * });
   * 
   * Automation Features:
   * - Scheduled backup configuration
   * - Backup retention policies
   * - Automation status monitoring
   * - Backup success/failure tracking
   * - Notification settings
   */
  getBackupStatus(): Observable<GetBackupStatusResponse> {
    return this.http.get<GetBackupStatusResponse>(`${this.API_URL}/resilience/backup/status`, {
      headers: this.getHeaders(),
      withCredentials: true
    });
  }
} 