/**
 * Admin Module DTOs (Data Transfer Objects)
 * 
 * This file contains all the response interfaces used by the admin module.
 * These are interfaces since they represent response data structures that
 * are returned to the frontend/admin interface.
 */

// ============================================================================
// USER MANAGEMENT DTOs
// ============================================================================

/**
 * Response interface for user management operations
 * 
 * Used by the admin interface to display and manage user accounts.
 * Includes pagination support for large user lists.
 */
export interface UserManagementResponseDto {
  /** Array of user objects with essential information for admin view */
  users: Array<{
    /** Unique identifier for the user */
    uuid: string;
    /** User's email address */
    email: string;
    /** User's role in the system */
    role: 'user' | 'admin';
    /** Whether the user's email has been verified */
    is_verified: boolean;
    /** When the user account was created */
    created_at: string;
    /** Last login timestamp (optional) */
    last_login_at?: string;
    /** User profile information (optional) */
    profile?: {
      /** Display name from user profile */
      display_name?: string;
    };
  }>;
  /** Pagination information for the user list */
  pagination: {
    /** Current page number */
    page: number;
    /** Number of items per page */
    limit: number;
    /** Total number of users */
    total: number;
    /** Total number of pages */
    total_pages: number;
  };
}

// ============================================================================
// SYSTEM METRICS DTOs
// ============================================================================

/**
 * Response interface for system metrics and analytics
 * 
 * Provides comprehensive system overview including user statistics,
 * request metrics, and system alerts for monitoring purposes.
 */
export interface SystemMetricsResponseDto {
  /** High-level system overview metrics */
  overview: {
    /** Total number of registered users */
    total_users: number;
    /** Number of active users (logged in recently) */
    active_users: number;
    /** Number of new user registrations today */
    new_users_today: number;
    /** Total number of API requests processed */
    total_requests: number;
    /** Error rate as a percentage */
    error_rate: number;
  };
  /** Chart data for visualizations */
  charts: {
    /** User growth data over time */
    user_growth: Array<{
      /** Date in ISO format */
      date: string;
      /** Number of users on this date */
      count: number;
    }>;
    /** Request volume by hour */
    request_volume: Array<{
      /** Hour identifier */
      hour: string;
      /** Number of requests in this hour */
      count: number;
    }>;
  };
  /** System alerts and notifications */
  alerts: Array<{
    /** Unique alert identifier */
    id: string;
    /** Alert severity level */
    type: 'error' | 'warning' | 'info';
    /** Alert message */
    message: string;
    /** When the alert was generated */
    timestamp: string;
    /** Whether the alert has been resolved */
    resolved: boolean;
  }>;
}

// ============================================================================
// AUDIT LOGS DTOs
// ============================================================================

/**
 * Response interface for audit logs
 * 
 * Provides detailed audit trail information for security and compliance
 * purposes. Includes pagination for large log datasets.
 */
export interface AuditLogsResponseDto {
  /** Array of audit log entries */
  logs: Array<{
    /** Unique log entry identifier */
    id: string;
    /** Type of action performed */
    action: string;
    /** UUID of the user who performed the action (optional) */
    user_uuid?: string;
    /** Email of the user who performed the action (optional) */
    user_email?: string;
    /** IP address of the request */
    ip_address: string;
    /** User agent string from the request */
    user_agent: string;
    /** When the action was performed */
    timestamp: string;
    /** Additional details about the action (optional) */
    details?: Record<string, any>;
  }>;
  /** Pagination information for the log list */
  pagination: {
    /** Current page number */
    page: number;
    /** Number of items per page */
    limit: number;
    /** Total number of log entries */
    total: number;
    /** Total number of pages */
    total_pages: number;
  };
} 