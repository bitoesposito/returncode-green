/**
 * Modelli per le funzioni amministrative PANDOM
 * Basati sulla struttura reale del backend
 */

import { ApiResponse, PaginationResponse } from './api-base.models';
import { UserRole } from './auth.models';

/**
 * Stati di salute del sistema
 */
export type SystemHealthStatus = 'healthy' | 'degraded' | 'down';

/**
 * Tipi di alert
 */
export type AlertType = 'error' | 'warning' | 'info' | 'success';

/**
 * Metriche di sistema di base
 */
export interface SystemMetricsResponse {
  overview: {
    total_users: number;
    active_users: number;
    new_users_today: number;
    total_requests: number;
    error_rate: number;
  };
  charts: {
    user_growth: Array<{date: string, count: number}>;
    request_volume: Array<{hour: string, count: number}>;
  };
  alerts: Array<{
    id: string;
    type: AlertType;
    message: string;
    timestamp: string;
    resolved: boolean;
  }>;
}

/**
 * Metriche di sistema dettagliate
 */
export interface DetailedSystemMetricsResponse {
  system: {
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    averageResponseTime: number;
    errorRate: number;
    requestsPerMinute: number;
    uniqueUsers: number;
    topEndpoints: Array<{path: string, count: number}>;
    errorBreakdown: Array<{statusCode: number, count: number}>;
  };
  hourly: Array<{
    hour: string;
    requests: number;
    errors: number;
    avgResponseTime: number;
    uniqueUsers: number;
  }>;
  alerts: Array<{
    id: string;
    type: AlertType;
    message: string;
    timestamp: string;
    resolved: boolean;
  }>;
  timestamp: string;
}

/**
 * Dati per la gestione utenti (admin)
 */
export interface UserManagementResponse {
  users: Array<{
    uuid: string;
    email: string;
    role: UserRole;
    is_verified: boolean;
    created_at: string;
    last_login_at?: string;
    profile?: {
      uuid?: string;
      display_name?: string;
      bio?: string;
    };
  }>;
  pagination: PaginationResponse;
}

/**
 * Log di audit
 */
export interface AuditLog {
  id: string;
  action: string;
  user_uuid: string;
  user_email: string;
  ip_address: string;
  user_agent: string;
  timestamp: string;
  details: any;
  resource_type?: string;
  resource_id?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Risposta con log di audit
 */
export interface AuditLogsResponse {
  logs: AuditLog[];
  pagination: PaginationResponse;
}

// Tipi per le chiamate API
export type GetMetricsResponse = ApiResponse<SystemMetricsResponse>;
export type GetDetailedMetricsResponse = ApiResponse<DetailedSystemMetricsResponse>;
export type GetUserManagementResponse = ApiResponse<UserManagementResponse>;
export type GetAuditLogsResponse = ApiResponse<AuditLogsResponse>;
export type DeleteUserResponse = ApiResponse<null>; 