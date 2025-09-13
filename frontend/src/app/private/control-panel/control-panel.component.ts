import { Component, OnInit, OnDestroy } from '@angular/core';
import { NavBarComponent } from '../nav-bar/nav-bar.component';
import { CommonModule } from '@angular/common';
import { TabViewModule } from 'primeng/tabview';
import { ButtonModule } from 'primeng/button';
import { AuthService } from '../../services/auth.service';
import { SecurityService } from '../../services/security.service';
import { SecuritySession, SecurityLog } from '../../models/security.models';
import { ResilienceService } from '../../services/resilience.service';
import { AdminService } from '../../services/admin.service';
import { DialogModule } from 'primeng/dialog';
import { Router } from '@angular/router';
import { TranslateModule, TranslateService } from '@ngx-translate/core';
import { NotificationService } from '../../services/notification.service';
import { ToastModule } from 'primeng/toast';
import { MessageService } from 'primeng/api';
import { TableModule } from 'primeng/table';
import { TagModule } from 'primeng/tag';
import { TooltipModule } from 'primeng/tooltip';
import { InputTextModule } from 'primeng/inputtext';
import { FormsModule } from '@angular/forms';
import { SystemStatusResponse, BackupResponse } from '../../models/resilience.models';
import { SystemMetricsResponse, DetailedSystemMetricsResponse } from '../../models/admin.models';
import { Subject, takeUntil, debounceTime, distinctUntilChanged } from 'rxjs';
import { PaginatorModule } from 'primeng/paginator';
import { CookieAuthService } from '../../services/cookie-auth.service';

/**
 * UserProfile Component
 * 
 * Gestisce il profilo utente, sessioni di sicurezza, log di sicurezza,
 * stato del sistema e gestione dei backup.
 */
@Component({
  selector: 'app-control-panel',
  imports: [
    NavBarComponent,
    CommonModule,
    TabViewModule,
    ButtonModule,
    DialogModule,
    TranslateModule,
    ToastModule,
    TableModule,
    TagModule,
    TooltipModule,
    InputTextModule,
    FormsModule,
    PaginatorModule
  ],
  providers: [MessageService, NotificationService],
  templateUrl: './control-panel.component.html',
  styleUrl: './control-panel.component.scss'
})
export class ControlPanelComponent implements OnInit, OnDestroy {
  userProfile: any = null;
  user: any = null;
  sessions: SecuritySession[] = [];
  securityLogs: SecurityLog[] = [];
  systemStatus: SystemStatusResponse | null = null;
  isLoadingSystemStatus: boolean = false;
  adminMetrics: SystemMetricsResponse | null = null;
  detailedMetrics: DetailedSystemMetricsResponse | null = null;
  isLoadingAdminMetrics: boolean = false;
  isLoadingDetailedMetrics: boolean = false;
  
  // Backup management
  backups: BackupResponse[] = [];
  isLoadingBackups: boolean = false;
  isCreatingBackup: boolean = false;
  isRestoringBackup: boolean = false;
  selectedBackupForRestore: BackupResponse | null = null;
  isRestoreDialogVisible: boolean = false;
  isBackupManagementDialogVisible: boolean = false;
  backupsPage: number = 1;
  backupsRows: number = 10;
  backupsTotal: number = 0;
  isEditDialogVisible: boolean = false; 
  isDownloadDialogVisible: boolean = false;
  isDeleteDialogVisible: boolean = false;
  isSecurityLogsDialogVisible: boolean = false;
  isDownloading: boolean = false;
  isChangePasswordDialogVisible: boolean = false;
  isProcessing: boolean = false;
  isLoadingSecurityLogs: boolean = false;
  securityLogsPage: number = 1;
  securityLogsRows: number = 10;
  securityLogsTotal: number = 0;
  auditLogs: any[] = [];
  isAuditLogsDialogVisible: boolean = false;
  isLoadingAuditLogs: boolean = false;
  auditLogsPage: number = 1;
  auditLogsRows: number = 10;
  auditLogsTotal: number = 0;
  
  // User management
  users: any[] = [];
  isUserManagementDialogVisible: boolean = false;
  isLoadingUsers: boolean = false;
  usersPage: number = 1;
  usersRows: number = 10;
  usersTotal: number = 0;
  userSearchQuery: string = '';
  isDeletingUser: boolean = false;
  selectedUserForAction: any = null;

  isLoadingProfile: boolean = false;

  // Destroy subject for proper cleanup
  private destroy$ = new Subject<void>();
  
  // Search subject for reactive search
  private searchSubject$ = new Subject<string>();

  get activeSessionsCount(): number {
    return this.sessions.filter(session => session.is_active).length;
  }

  constructor(
    private authService: CookieAuthService,
    private securityService: SecurityService,
    private resilienceService: ResilienceService,
    private adminService: AdminService,
    private router: Router,
    private translateService: TranslateService,
    private notificationService: NotificationService
  ) {}

  ngOnInit(): void {
    this.isLoadingProfile = true;
    this.authService.forceRefreshUserData().subscribe({
      next: (data) => {
        if (data.data) {
          this.user = data.data.user;
          this.userProfile = data.data.profile;
        } else {
          this.user = null;
          this.userProfile = null;
        }
        this.isLoadingProfile = false;
      },
      error: (err) => {
        this.user = null;
        this.userProfile = null;
        this.isLoadingProfile = false;
      }
    });
    this.loadSessions();
    
    // Setup reactive search with debounce and distinctUntilChanged
    this.searchSubject$.pipe(
      debounceTime(300), // Wait 300ms after user stops typing
      distinctUntilChanged(), // Only emit if value actually changed
      takeUntil(this.destroy$)
    ).subscribe(searchQuery => {
      this.userSearchQuery = searchQuery;
      // Only search if dialog is visible to prevent unnecessary requests
      if (this.isUserManagementDialogVisible) {
        this.loadUsers(1, this.usersRows); // Reset to first page when searching
      }
    });
  }

  // Metodo da chiamare dopo login
  refreshUserAfterLogin(): void {
    this.isLoadingProfile = true;
    this.authService.forceRefreshUserData().subscribe({
      next: (data) => {
        if (data.data) {
          this.user = data.data.user;
          this.userProfile = data.data.profile;
        } else {
          this.user = null;
          this.userProfile = null;
        }
        this.isLoadingProfile = false;
      },
      error: (err) => {
        this.user = null;
        this.userProfile = null;
        this.isLoadingProfile = false;
      }
    });
  }

  // Metodo da chiamare dopo logout
  clearUserAfterLogout(): void {
    this.user = null;
    this.userProfile = null;
    this.isLoadingProfile = false;
    this.authService.forceLogout();
  }

  ngOnDestroy(): void {
    // Cleanup subscriptions to prevent memory leaks
    this.destroy$.next();
    this.destroy$.complete();
  }

  /**
   * Handle tab change events
   * @param event - Tab change event
   */
  onTabChange(event: any): void {
    // Solo admin può caricare dati admin
    if (event.index === 1 && this.user?.role === 'admin') {
      this.loadAdminData();
    }
    if (event.index === 2 && this.user?.role === 'admin' && !this.systemStatus) {
      this.loadSystemStatus();
    }
  }

  /**
   * Load user profile data
   */
  private loadUserProfile(): void {
    this.authService.handleUserSwitch()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
      next: (data) => {
        if (data.data) {
          this.user = data.data.user;
          this.userProfile = data.data.profile;
        }
      },
      error: (err) => {
          this.notificationService.handleError(err, 'profile.load.error');
      }
    });
  }

  /**
   * Load user sessions
   */
  private loadSessions(): void {
    this.securityService.getSessions()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
      next: (data: any) => {
        if (data.data) {
          this.sessions = data.data.sessions || [];
        }
      },
      error: (err: any) => {
          this.notificationService.handleError(err, 'profile.sessions.error');
      }
    });
  }

  /**
   * Load security logs
   * @param page - Page number
   * @param rows - Number of rows per page
   */
  loadSecurityLogs(page: number = 1, rows: number = 10): void {
    this.isLoadingSecurityLogs = true;
    this.securityService.getSecurityLogs(page, rows)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
      next: (data: any) => {
        if (data.data) {
          this.securityLogs = data.data.logs || [];
          this.securityLogsTotal = data.data.pagination?.total || 0;
          this.securityLogsPage = data.data.pagination?.page || page;
          this.securityLogsRows = data.data.pagination?.limit || rows;
        }
        this.isLoadingSecurityLogs = false;
      },
      error: (err: any) => {
        this.notificationService.handleError(err, 'profile.security-logs.error');
        this.isLoadingSecurityLogs = false;
      }
    });
  }

  /**
   * Load system status
   */
  loadSystemStatus(): void {
    this.isLoadingSystemStatus = true;
    this.resilienceService.getSystemStatus()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
      next: (data: any) => {
        if (data.data) {
          this.systemStatus = data.data;
        }
        this.isLoadingSystemStatus = false;
      },
      error: (err: any) => {
          this.notificationService.handleError(err, 'profile.system-status.error');
        this.isLoadingSystemStatus = false;
      }
    });
  }

  /**
   * Load admin data
   */
  loadAdminData(): void {
    if (this.user?.role !== 'admin') {
      return;
    }
    this.isLoadingAdminMetrics = true;
    this.isLoadingDetailedMetrics = true;
    
    // Carica metriche base
    this.adminService.getMetrics()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
      next: (data: any) => {
        if (data.data) {
          this.adminMetrics = data.data;
        }
        this.isLoadingAdminMetrics = false;
      },
      error: (err: any) => {
          this.notificationService.handleError(err, 'profile.administration.error');
        this.isLoadingAdminMetrics = false;
      }
    });

    // Carica metriche dettagliate
    this.adminService.getDetailedMetrics()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
      next: (data: any) => {
        if (data.data) {
          this.detailedMetrics = data.data;
        }
        this.isLoadingDetailedMetrics = false;
      },
      error: (err: any) => {
          this.notificationService.handleError(err, 'profile.administration.error');
        this.isLoadingDetailedMetrics = false;
      }
    });
  }

  /**
   * Toggle dialog visibility
   * @param key - Dialog key
   */
  toggleDialog(key: string): void {
    switch (key) {
      case 'edit':
        this.isEditDialogVisible = !this.isEditDialogVisible;
        break;
      case 'download':
        this.isDownloadDialogVisible = !this.isDownloadDialogVisible;
        break;
      case 'delete':
        this.isDeleteDialogVisible = !this.isDeleteDialogVisible;
        break;
      case 'security':
        this.isSecurityLogsDialogVisible = !this.isSecurityLogsDialogVisible;
        if (this.isSecurityLogsDialogVisible) {
          this.loadSecurityLogs(1, this.securityLogsRows);
        }
        break;
      case 'change-password':
        this.isChangePasswordDialogVisible = !this.isChangePasswordDialogVisible;
        break;
      case 'audit-logs':
        this.isAuditLogsDialogVisible = !this.isAuditLogsDialogVisible;
        if (this.isAuditLogsDialogVisible) {
          this.loadAuditLogs(1, this.auditLogsRows);
        }
        break;
      case 'user-management':
        this.isUserManagementDialogVisible = !this.isUserManagementDialogVisible;
        if (this.isUserManagementDialogVisible) {
          this.loadUsers(1, this.usersRows);
        }
        break;
      default:
        break;
    }
  }

  /**
   * Download personal data from the server
   */
  downloadPersonalData(): void {
    // Prevent multiple simultaneous downloads
    if (this.isDownloading) {
      return;
    }
    
    this.isDownloading = true;
    this.securityService.downloadData().subscribe({
      next: (response) => {
        if (response.success && response.data?.download_url) {
          
          // Close the modal first
          this.isDownloadDialogVisible = false;
          
          // Open download URL in new window/tab (better Firefox compatibility)
          window.open(response.data.download_url, '_blank');
          
          // Show success notification after modal is closed
          setTimeout(() => {
            this.notificationService.handleSuccess('profile.download.success');
          }, 100);
        } else {
          this.notificationService.handleError(response, 'profile.download.error');
        }
        this.isDownloading = false;
      },
      error: (error) => {
        this.notificationService.handleError(error, 'profile.download.error');
        this.isDownloading = false;
      }
    });
  }

  

  /**
   * Request password change by sending reset email
   */
  requestPasswordChange(): void {
    if (!this.user?.email) {
      this.notificationService.handleError(null, 'profile.change-password.no-email');
      return;
    }

    this.isProcessing = true;
    
    this.authService.forgotPassword({ email: this.user.email }).subscribe({
      next: (response) => {
        if (response.success) {
          // Close the modal first
          this.isChangePasswordDialogVisible = false;
          
          // Show success notification
          this.notificationService.handleSuccess('profile.change-password.email-sent');
          
          // Keep isProcessing true until redirect
          // Logout the user and redirect after toast is shown
          setTimeout(() => {
            this.authService.logout().subscribe({
              next: () => {
                this.authService.clearAuthStatus();
                this.router.navigate(['/reset'], { 
                  queryParams: { email: this.user.email } 
                });
              },
              error: () => {
                this.authService.clearAuthStatus();
            this.router.navigate(['/reset'], { 
              queryParams: { email: this.user.email } 
                });
              }
            });
          }, 2000);
        } else {
          this.isProcessing = false;
          this.notificationService.handleError(response, 'profile.change-password.email-failed');
        }
      },
      error: (error) => {
        this.isProcessing = false;
        this.notificationService.handleError(error, 'profile.change-password.email-failed');
      }
    });
  }

  /**
   * Delete user account
   */
  deleteAccount(): void {
    this.isProcessing = true;
    
    this.securityService.deleteAccount().subscribe({
      next: (response) => {
        if (response.success) {
          // Close the modal first
          this.isDeleteDialogVisible = false;
          
          // Show success notification
          this.notificationService.handleSuccess('profile.delete-account.success');
          
          // Keep isProcessing true until redirect
          // Logout the user and redirect after toast is shown
          setTimeout(() => {
            // Immediately clear user data and authentication state
            this.user = null;
            this.userProfile = null;
            this.authService.forceLogout();
            
            // Call server logout (but don't wait for it)
            this.authService.logout().subscribe({
              next: () => {
                // Server logout successful, redirect
                this.router.navigate(['/login']);
              },
              error: () => {
                // Server logout failed, but we've already cleared local state
                // Redirect anyway
                this.router.navigate(['/login']);
              }
            });
          }, 2000);
        } else {
          this.isProcessing = false;
          this.notificationService.handleError(response, 'profile.delete-account.failed');
        }
      },
      error: (error) => {
        this.isProcessing = false;
        this.notificationService.handleError(error, 'profile.delete-account.failed');
      }
    });
  }

  /**
   * Get the severity for the status tag
   */
  getSecurityStatusSeverity(success: boolean): string {
    return success ? 'success' : 'danger';
  }

  /**
   * Get the translated status text
   */
  getStatusText(success: boolean): string {
    return 'profile.security-logs.status.' + (success ? 'SUCCESS' : 'FAILED');
  }

  /**
   * Format timestamp for display
   */
  formatTimestamp(timestamp: string): string {
    return new Date(timestamp).toLocaleString();
  }

  /**
   * Truncate user agent for display
   */
  truncateUserAgent(userAgent: string): string {
    return userAgent.length > 50 ? userAgent.substring(0, 50) + '...' : userAgent;
  }

  /**
   * Get system status severity for PrimeNG tag
   * @param status - Service status
   * @returns Severity string
   */
  getSystemStatusSeverity(status: 'healthy' | 'degraded' | 'down'): string {
    switch (status) {
      case 'healthy':
        return 'success';
      case 'degraded':
        return 'warning';
      case 'down':
        return 'danger';
      default:
        return 'info';
    }
  }

  /**
   * Format uptime from seconds to human readable format
   * @param uptime - Uptime in seconds
   * @returns Formatted uptime string
   */
  formatUptime(uptime: number): string {
    const days = Math.floor(uptime / 86400);
    const hours = Math.floor((uptime % 86400) / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = Math.floor(uptime % 60);

    if (days > 0) {
      return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
      return `${hours}h ${minutes}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds}s`;
    } else {
      return `${seconds}s`;
    }
  }

  /**
   * Format timestamp to local date string
   * @param timestamp - ISO timestamp
   * @returns Formatted date string
   */
  formatSystemTimestamp(timestamp: string): string {
    return new Date(timestamp).toLocaleString();
  }

  loadAuditLogs(page: number = 1, rows: number = 10) {
    this.isLoadingAuditLogs = true;
    this.adminService.getAuditLogs(page, rows).subscribe({
      next: (data: any) => {
        if (data.data) {
          this.auditLogs = data.data.logs || [];
          this.auditLogsTotal = data.data.pagination?.total || 0;
          this.auditLogsPage = data.data.pagination?.page || page;
          this.auditLogsRows = data.data.pagination?.limit || rows;
        }
        this.isLoadingAuditLogs = false;
      },
      error: (err: any) => {
        this.isLoadingAuditLogs = false;
        this.notificationService.handleError(err, 'profile.audit-logs.error');
      }
    });
  }

  onAuditLogsPageChange(event: any) {
    
    // Calcola la pagina corrente basandosi su first e rows
    // PrimeNG usa first (indice 0-based) e rows per calcolare la pagina
    const newPage = Math.floor(event.first / event.rows) + 1;
    
    // Verifica che la pagina sia valida
    if (isNaN(newPage) || newPage < 1) {
      return;
    }
    
    this.loadAuditLogs(newPage, event.rows);
  }

  onSecurityLogsPageChange(event: any) {
    
    // Calcola la pagina corrente basandosi su first e rows
    // PrimeNG usa first (indice 0-based) e rows per calcolare la pagina
    const newPage = Math.floor(event.first / event.rows) + 1;
    
    // Verifica che la pagina sia valida
    if (isNaN(newPage) || newPage < 1) {
      return;
    }
    
    this.loadSecurityLogs(newPage, event.rows);
  }

  onSecurityLogsPaginatorChange(event: any) {
    const newPage = Math.floor(event.first / event.rows) + 1;
    this.loadSecurityLogs(newPage, event.rows);
  }

  // User Management Methods
  loadUsers(page: number = 1, rows: number = 10) {
    this.isLoadingUsers = true;
    this.adminService.getUsers(page, rows, this.userSearchQuery).subscribe({
      next: (data: any) => {
        if (data.data) {
          this.users = data.data.users || [];
          this.usersTotal = data.data.pagination?.total || 0;
          this.usersPage = data.data.pagination?.page || page;
          this.usersRows = data.data.pagination?.limit || rows;
        }
        this.isLoadingUsers = false;
      },
      error: (err: any) => {
        this.isLoadingUsers = false;
        this.notificationService.handleError(err, 'profile.user-management.error');
      }
    });
  }

  onUsersPageChange(event: any) {
    const newPage = Math.floor(event.first / event.rows) + 1;
    if (isNaN(newPage) || newPage < 1) {
      return;
    }
    this.loadUsers(newPage, event.rows);
  }

  onUsersPaginatorChange(event: any) {
    const newPage = Math.floor(event.first / event.rows) + 1;
    this.loadUsers(newPage, event.rows);
  }

  onUserSearch() {
    // Trigger reactive search only if dialog is visible
    if (this.isUserManagementDialogVisible) {
      this.searchSubject$.next(this.userSearchQuery);
    }
  }
  
  onSearchInputChange(event: any) {
    // Trigger search on input change only if dialog is visible
    if (this.isUserManagementDialogVisible) {
      this.searchSubject$.next(event.target.value);
    }
  }

  deleteUser(user: any) {
    this.selectedUserForAction = user;
    this.isDeletingUser = true;
    
    this.adminService.deleteUser(user.uuid).subscribe({
      next: (data: any) => {
        this.notificationService.handleSuccess('profile.user-management.delete-success');
        this.loadUsers(this.usersPage, this.usersRows); // Reload current page
        this.isDeletingUser = false;
        this.selectedUserForAction = null;
      },
      error: (err: any) => {
        this.notificationService.handleError(err, 'profile.user-management.delete-error');
        this.isDeletingUser = false;
        this.selectedUserForAction = null;
      }
    });
  }

  getRoleSeverity(role: string): string {
    switch (role) {
      case 'admin':
        return 'danger';
      case 'user':
        return 'info';
      default:
        return 'secondary';
    }
  }

  getUserDisplayName(user: any): string {
    if (user.first_name && user.last_name) {
      return `${user.first_name} ${user.last_name}`;
    } else if (user.first_name) {
      return user.first_name;
    } else if (user.last_name) {
      return user.last_name;
    } else if (user.profile?.display_name) {
      return user.profile.display_name;
    } else {
      return user.email;
    }
  }

  // Backup Management Methods
  loadBackups(page: number = 1, rows: number = 10) {
    this.isLoadingBackups = true;
    this.resilienceService.listBackups(page, rows).subscribe({
      next: (data: any) => {
        if (data.data) {
          this.backups = data.data.backups || [];
          this.backupsTotal = data.data.pagination?.total || 0;
          this.backupsPage = data.data.pagination?.page || page;
          this.backupsRows = data.data.pagination?.limit || rows;
        }
        this.isLoadingBackups = false;
      },
      error: (err: any) => {
        this.notificationService.handleError(err, 'profile.system-status.backup-list-failed');
        this.isLoadingBackups = false;
      }
    });
  }

  createBackup() {
    this.isCreatingBackup = true;
    this.resilienceService.createBackup().subscribe({
      next: (data: any) => {
        this.notificationService.handleSuccess('profile.system-status.backup-created');
        this.loadBackups(this.backupsPage, this.backupsRows); // Reload current page
        this.isCreatingBackup = false;
      },
      error: (err: any) => {
        this.notificationService.handleError(err, 'profile.system-status.backup-creation-failed');
        this.isCreatingBackup = false;
      }
    });
  }

  restoreBackup(backup: BackupResponse) {
    this.selectedBackupForRestore = backup;
    this.isRestoreDialogVisible = true;
  }

  confirmRestoreBackup() {
    if (!this.selectedBackupForRestore) return;
    
    this.isRestoringBackup = true;
    this.resilienceService.restoreBackup(this.selectedBackupForRestore.backup_id).subscribe({
      next: (data: any) => {
        this.notificationService.handleSuccess('profile.system-status.backup-restored');
        this.loadBackups(this.backupsPage, this.backupsRows); // Reload current page
        this.isRestoringBackup = false;
        this.isRestoreDialogVisible = false;
        this.selectedBackupForRestore = null;
      },
      error: (err: any) => {
        this.notificationService.handleError(err, 'profile.system-status.backup-restore-failed');
        this.isRestoringBackup = false;
        this.isRestoreDialogVisible = false;
        this.selectedBackupForRestore = null;
      }
    });
  }

  cancelRestoreBackup() {
    this.isRestoreDialogVisible = false;
    this.selectedBackupForRestore = null;
  }

  openBackupManagementDialog() {
    this.isBackupManagementDialogVisible = true;
    this.loadBackups(1, this.backupsRows); // Load first page
  }

  onBackupsPageChange(event: any) {
    const newPage = Math.floor(event.first / event.rows) + 1;
    if (isNaN(newPage) || newPage < 1) {
      return;
    }
    this.loadBackups(newPage, event.rows);
  }

  formatBackupSize(size: number): string {
    if (size === 0) return 'Unknown';
    const units = ['B', 'KB', 'MB', 'GB'];
    let unitIndex = 0;
    let fileSize = size;
    
    while (fileSize >= 1024 && unitIndex < units.length - 1) {
      fileSize /= 1024;
      unitIndex++;
    }
    
    return `${fileSize.toFixed(1)} ${units[unitIndex]}`;
  }

  formatBackupDate(dateString: string): string {
    return new Date(dateString).toLocaleString();
  }

  // Method to track sessions by their ID
  trackBySessionId(index: number, session: any): any {
    return session.id;
  }

  onAuditLogsPaginatorChange(event: any) {
    const newPage = Math.floor(event.first / event.rows) + 1;
    this.loadAuditLogs(newPage, event.rows);
  }

  onBackupsPaginatorChange(event: any) {
    const newPage = Math.floor(event.first / event.rows) + 1;
    this.loadBackups(newPage, event.rows);
  }
}
