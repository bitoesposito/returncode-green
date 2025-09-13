import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { MessageService } from 'primeng/api';
import { ApiResponse } from '../models/api-base.models';
import { TranslateService } from '@ngx-translate/core';

/**
 * Interface for debounce tracking
 * 
 * Maps notification keys to timestamps for debouncing
 * duplicate notifications within a specified time window.
 */
interface DebounceMap {
  [key: string]: number;
}

/**
 * Notification Service
 * 
 * Centralized notification management service that handles all user-facing
 * messages, alerts, and notifications throughout the application. Provides
 * consistent notification handling with internationalization support.
 * 
 * Features:
 * - Multi-type notifications (success, error, info, warning)
 * - Internationalization support with translation keys
 * - Debounced notifications to prevent spam
 * - API response handling
 * - Error handling with fallback messages
 * - Offline-specific notifications
 * - Centralized message management
 * 
 * Notification Types:
 * - Success: Positive feedback for successful operations
 * - Error: Error messages for failed operations
 * - Info: Informational messages for general updates
 * - Warning: Warning messages for potential issues
 * 
 * Internationalization:
 * - Uses translation keys for all messages
 * - Supports parameter interpolation
 * - Fallback to default messages
 * - Consistent message formatting
 * 
 * Debouncing:
 * - Prevents duplicate notifications
 * - Configurable debounce time window
 * - Key-based debouncing for specific notifications
 * - Automatic cleanup of old entries
 * 
 * Usage:
 * - Inject service in components
 * - Use translation keys for messages
 * - Handle API responses automatically
 * - Provide consistent user feedback
 * 
 * @example
 * // Show success message
 * this.notificationService.handleSuccess('user.profile.updated');
 * 
 * @example
 * // Handle API response
 * this.apiService.updateUser(data).subscribe({
 *   next: (response) => this.notificationService.handleApiResponse(response, 'user.update.success'),
 *   error: (error) => this.notificationService.handleError(error, 'user.update.error')
 * });
 * 
 * @example
 * // Show debounced notification
 * this.notificationService.notifyOfflineSaved();
 */
@Injectable({
    providedIn: 'root'
})
export class NotificationService {
    // ============================================================================
    // PROPERTIES
    // ============================================================================

    /**
     * Map for tracking debounced notifications
     * Stores timestamps for notification keys to prevent duplicates
     */
    private debounceMap: DebounceMap = {};

    /**
     * Debounce time window in milliseconds
     * Notifications with the same key within this window are ignored
     */
    private debounceTime = 3000; // ms

    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================

    constructor(
        private messageService: MessageService,
        private http: HttpClient,
        private translate: TranslateService
    ) {}

    // ============================================================================
    // PRIVATE METHODS
    // ============================================================================

    /**
     * Show message with debouncing to prevent duplicate notifications
     * 
     * Checks if a notification with the same key was recently shown
     * and only displays the message if enough time has passed.
     * 
     * @param severity - Message type (success/error/info/warning)
     * @param key - Translation key for the message
     * @param params - Optional parameters for translation interpolation
     * @param debounceKey - Optional custom key for debouncing
     * 
     * @example
     * this.showMessageDebounced('success', 'user.saved', { name: 'John' });
     * 
     * Debouncing process:
     * - Checks if notification was recently shown
     * - Uses debounce key or generates from severity + key
     * - Updates timestamp if notification is shown
     * - Translates message with parameters
     * - Displays notification
     */
    private showMessageDebounced(severity: 'success' | 'error' | 'info' | 'warning', key: string, params?: any, debounceKey?: string): void {
        const now = Date.now();
        const dKey = debounceKey || key + severity;
        
        // Check if notification was recently shown
        if (this.debounceMap[dKey] && now - this.debounceMap[dKey] < this.debounceTime) {
            return;
        }
        
        // Update timestamp and show message
        this.debounceMap[dKey] = now;
        this.translate.get(key, params).subscribe((msg: string) => {
            this.showMessage(severity, msg);
        });
    }

    // ============================================================================
    // CORE NOTIFICATION METHODS
    // ============================================================================

    /**
     * Display a notification message with specified severity
     * 
     * Shows a notification using PrimeNG MessageService with
     * appropriate styling and translation support.
     * 
     * @param severity - Message type (success/error/info/warning)
     * @param message - Message text to display
     * 
     * @example
     * this.showMessage('success', 'Operation completed successfully');
     * this.showMessage('error', 'An error occurred');
     * this.showMessage('info', 'Please wait while we process your request');
     * this.showMessage('warning', 'Please check your input');
     * 
     * Message types:
     * - success: Green notification for successful operations
     * - error: Red notification for errors and failures
     * - info: Blue notification for informational messages
     * - warning: Orange notification for warnings and cautions
     */
    showMessage(severity: 'success' | 'error' | 'info' | 'warning', message: string): void {
        let summary = '';
        
        // Get appropriate summary based on severity
        switch (severity) {
            case 'success': 
                summary = this.translate.instant('notification.success'); 
                break;
            case 'error': 
                summary = this.translate.instant('notification.error'); 
                break;
            case 'info': 
                summary = this.translate.instant('notification.info'); 
                break;
            case 'warning': 
                summary = this.translate.instant('notification.warning'); 
                break;
            default: 
                summary = this.translate.instant('notification.info'); 
                break;
        }
        
        // Add message to PrimeNG message service
        this.messageService.add({ severity, summary, detail: message });
    }

    // ============================================================================
    // API RESPONSE HANDLING METHODS
    // ============================================================================

    /**
     * Handle API response and show appropriate notification
     * 
     * Automatically determines success or error based on API response
     * and shows the corresponding notification message.
     * 
     * @param response - API response object
     * @param key - Translation key for the default message
     * 
     * @example
     * this.apiService.createUser(userData).subscribe(response => {
     *   this.handleApiResponse(response, 'user.create.success');
     * });
     * 
     * Response handling:
     * - Checks response.success flag
     * - Shows success message if true
     * - Shows error message if false
     * - Uses response.message or fallback translation
     */
    handleApiResponse<T>(response: ApiResponse<T>, key: string): void {
        this.translate.get(key).subscribe((msg: string) => {
            if (response.success) {
                this.showMessage('success', response.message || msg);
            } else {
                this.showMessage('error', response.message || msg);
            }
        });
    }

    /**
     * Handle HTTP errors and show error notification
     * 
     * Extracts error message from various error response formats
     * and displays an appropriate error notification.
     * 
     * @param error - HTTP error object
     * @param key - Translation key for the fallback error message
     * 
     * @example
     * this.apiService.getData().subscribe({
     *   next: (data) => console.log(data),
     *   error: (error) => this.handleError(error, 'data.fetch.error')
     * });
     * 
     * Error extraction priority:
     * 1. error.error.message (standard API error format)
     * 2. error.error.data.message (nested API error format)
     * 3. error.error (string format, attempts JSON parsing)
     * 4. error.message (generic error message)
     * 5. Fallback translation key
     */
    handleError(error: any, key: string): void {
        this.translate.get(key).subscribe((msg: string) => {
            let errorMessage = msg;
            
            // Extract error message from various formats
            if (error?.error?.message) {
                errorMessage = error.error.message;
            } else if (error?.error?.data?.message) {
                errorMessage = error.error.data.message;
            } else if (typeof error?.error === 'string') {
                try {
                    errorMessage = JSON.parse(error.error).message || msg;
                } catch {
                    errorMessage = error.error;
                }
            } else if (error?.message) {
                errorMessage = error.message;
            }
            
            this.showMessage('error', errorMessage);
        });
    }

    // ============================================================================
    // CONVENIENCE METHODS
    // ============================================================================

    /**
     * Show success notification with translation
     * 
     * @param key - Translation key for the success message
     * @param params - Optional parameters for translation interpolation
     * 
     * @example
     * this.handleSuccess('user.profile.updated', { name: 'John' });
     */
    handleSuccess(key: string, params?: any): void {
        this.translate.get(key, params).subscribe((msg: string) => {
            this.showMessage('success', msg);
        });
    }

    /**
     * Show warning notification with translation
     * 
     * @param key - Translation key for the warning message
     * @param params - Optional parameters for translation interpolation
     * 
     * @example
     * this.handleWarning('user.session.expiring', { time: '5 minutes' });
     */
    handleWarning(key: string, params?: any): void {
        this.translate.get(key, params).subscribe((msg: string) => {
            this.showMessage('warning', msg);
        });
    }

    /**
     * Show info notification with translation
     * 
     * @param key - Translation key for the info message
     * @param params - Optional parameters for translation interpolation
     * 
     * @example
     * this.handleInfo('system.maintenance.scheduled', { time: '2:00 AM' });
     */
    handleInfo(key: string, params?: any): void {
        this.translate.get(key, params).subscribe((msg: string) => {
            this.showMessage('info', msg);
        });
    }

    // ============================================================================
    // OFFLINE-SPECIFIC NOTIFICATION METHODS
    // ============================================================================

    /**
     * Notify that data was saved offline
     * 
     * Shows a debounced success message when data is saved
     * to local storage for offline functionality.
     * 
     * @example
     * this.notifyOfflineSaved();
     * // Shows: "Data saved for offline use"
     */
    notifyOfflineSaved(): void {
        this.showMessageDebounced('success', 'offline.saved');
    }

    /**
     * Notify that data was queued for sync
     * 
     * Shows a debounced info message when data is queued
     * for synchronization when connection is restored.
     * 
     * @example
     * this.notifyOfflineQueued();
     * // Shows: "Data queued for synchronization"
     */
    notifyOfflineQueued(): void {
        this.showMessageDebounced('info', 'offline.queued');
    }

    /**
     * Notify offline operation error
     * 
     * Shows a debounced error message when an offline
     * operation fails.
     * 
     * @example
     * this.notifyOfflineError();
     * // Shows: "Offline operation failed"
     */
    notifyOfflineError(): void {
        this.showMessageDebounced('error', 'offline.error');
    }

    /**
     * Notify successful sync batch
     * 
     * Shows a success message when a batch of offline
     * data is successfully synchronized.
     * 
     * @param count - Number of items synchronized
     * 
     * @example
     * this.notifySyncBatch(5);
     * // Shows: "5 items synchronized successfully"
     */
    notifySyncBatch(count: number): void {
        this.handleSuccess('offline.sync_batch', { count });
    }

    /**
     * Notify sync error
     * 
     * Shows a warning message when synchronization
     * encounters an error.
     * 
     * @example
     * this.notifySyncError();
     * // Shows: "Synchronization error occurred"
     */
    notifySyncError(): void {
        this.handleWarning('offline.sync_error');
    }

    /**
     * Notify connection state change
     * 
     * Shows appropriate notification based on online/offline
     * connection status.
     * 
     * @param isOnline - Whether the application is online
     * 
     * @example
     * this.notifyOfflineState(true);  // Shows: "Connection restored"
     * this.notifyOfflineState(false); // Shows: "Working offline"
     */
    notifyOfflineState(isOnline: boolean): void {
        if (isOnline) {
            this.handleInfo('offline.online');
        } else {
            this.handleWarning('offline.offline');
        }
    }
}