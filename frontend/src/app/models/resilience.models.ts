/**
 * Modelli per la resilienza PANDOM
 * Basati sulla struttura reale del backend
 */

import { ApiResponse, PaginationResponse } from './api-base.models';

/**
 * Stati di salute del sistema
 */
export type SystemHealthStatus = 'healthy' | 'degraded' | 'down';

/**
 * Stati di backup
 */
export type BackupStatus = 'completed' | 'restored' | 'available';

/**
 * Stati di automazione
 */
export type AutomationStatus = 'running' | 'stopped';

/**
 * Risposta per lo stato del sistema
 */
export interface SystemStatusResponse {
  status: SystemHealthStatus;
  timestamp: string;
  version: string;
  uptime: number;
  services: {
    database: SystemHealthStatus;
    storage: SystemHealthStatus;
    email: SystemHealthStatus;
  };
}

/**
 * Risposta per le operazioni di backup
 */
export interface BackupResponse {
  backup_id: string;
  backup_file: string;
  backup_size: number;
  created_at: string;
  status: BackupStatus;
}

/**
 * Risposta per lo stato dei backup
 */
export interface BackupStatusResponse {
  last_backup: {
    timestamp: string;
    file: string;
    size: number;
    checksum_valid: boolean;
  } | null;
  total_backups: number;
  total_size: number;
  retention_policy: {
    days: number;
    next_cleanup: string;
  };
  automation_status: {
    backup_cron: AutomationStatus;
    cleanup_cron: AutomationStatus;
    verify_cron: AutomationStatus;
  };
}

/**
 * Risposta per la lista backup con paginazione
 */
export interface BackupListResponse {
  backups: BackupResponse[];
  pagination: {
    page: number;
    limit: number;
    total: number;
  };
}

// Tipi per le chiamate API
export type GetSystemStatusResponse = ApiResponse<SystemStatusResponse>;
export type CreateBackupResponse = ApiResponse<BackupResponse>;
export type ListBackupsResponse = ApiResponse<BackupListResponse>;
export type RestoreBackupResponse = ApiResponse<BackupResponse>;
export type GetBackupStatusResponse = ApiResponse<BackupStatusResponse>; 