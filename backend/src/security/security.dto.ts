// Response DTOs for SECURITY module
// These are interfaces since they represent response data structures

/**
 * Download Data Storage Interface
 * 
 * Defines the structure for temporary data storage during GDPR data export.
 * In production environments, this should be replaced with Redis or a database
 * for better persistence and scalability.
 * 
 * @example
 * {
 *   userId: "user-uuid",
 *   data: { user: {...}, profile: {...}, security_logs: [...] },
 *   expiresAt: new Date("2024-01-16T10:30:00.000Z")
 * }
 */
export interface DownloadData {
  /** User ID for the data export */
  userId: string;
  /** Complete user data for export */
  data: any;
  /** Expiration timestamp for the download link */
  expiresAt: Date;
}

/**
 * Security Logs Response DTO
 * 
 * Defines the structure for security activity logs responses.
 * Provides paginated access to user security events and activities
 * for transparency and compliance purposes.
 * 
 * @example
 * {
 *   "logs": [
 *     {
 *       "id": "log_1234567890",
 *       "action": "USER_LOGIN_SUCCESS",
 *       "ip_address": "192.168.1.100",
 *       "user_agent": "Mozilla/5.0...",
 *       "timestamp": "2024-01-15T10:30:00.000Z",
 *       "success": true,
 *       "details": { "device": "Desktop", "location": "IT" }
 *     }
 *   ],
 *   "pagination": {
 *     "page": 1,
 *     "limit": 10,
 *     "total": 150,
 *     "total_pages": 15
 *   }
 * }
 */
export interface SecurityLogsResponseDto {
  /** Array of security log entries */
  logs: Array<{
    /** Unique identifier for the log entry */
    id: string;
    /** Type of security action performed */
    action: string;
    /** IP address of the client */
    ip_address: string;
    /** User agent string of the client */
    user_agent: string;
    /** ISO timestamp of the event */
    timestamp: string;
    /** Whether the action was successful */
    success: boolean;
    /** Additional details about the event */
    details?: Record<string, any>;
  }>;
  /** Pagination information */
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

/**
 * User Sessions Response DTO
 * 
 * Defines the structure for user session information responses.
 * Provides details about active and recent user sessions for
 * security monitoring and account management.
 * 
 * @example
 * {
 *   "sessions": [
 *     {
 *       "id": "current",
 *       "device_info": "Current Session",
 *       "ip_address": "192.168.1.100",
 *       "created_at": "2024-01-15T10:30:00.000Z",
 *       "last_used": "2024-01-15T11:45:00.000Z",
 *       "is_current": true
 *     }
 *   ]
 * }
 */
export interface SessionsResponseDto {
  /** Array of user session information */
  sessions: Array<{
    /** Unique identifier for the session */
    id: string;
    /** Device or browser information */
    device_info: string;
    /** IP address of the session */
    ip_address: string;
    /** ISO timestamp when session was created */
    created_at: string;
    /** ISO timestamp of last session activity */
    last_used: string;
    /** Whether this is the current active session */
    is_current: boolean;
  }>;
}

/**
 * Data Download Response DTO
 * 
 * Defines the structure for GDPR data export responses.
 * Provides secure download URLs with expiration times for
 * user data export compliance.
 * 
 * @example
 * {
 *   "download_url": "http://localhost:3000/security/downloads/user-data-uuid-1234567890.json",
 *   "expires_at": "2024-01-16T10:30:00.000Z",
 *   "file_size": 2048,
 *   "format": "json"
 * }
 */
export interface DownloadDataResponseDto {
  /** Secure URL for downloading user data */
  download_url: string;
  /** ISO timestamp when the download link expires */
  expires_at: string;
  /** Size of the data file in bytes */
  file_size: number;
  /** Format of the exported data */
  format: 'json' | 'csv' | 'xml' | 'zip';
} 