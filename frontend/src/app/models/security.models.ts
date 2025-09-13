/**
 * Modelli per la sicurezza PANDOM
 * Basati sulla struttura reale del backend
 */

import { ApiResponse, PaginationResponse } from './api-base.models';

/**
 * Sessione di sicurezza
 */
export interface SecuritySession {
  id: string;
  device: string;
  ip_address: string;
  user_agent: string;
  created_at: string;
  expires_at: string;
  is_active: boolean;
}

/**
 * Log di sicurezza
 */
export interface SecurityLog {
  id: string;
  action: string;
  ip_address: string;
  user_agent: string;
  timestamp: string;
  success: boolean;
  details?: Record<string, any>;
}

/**
 * Risposta con log di sicurezza
 */
export interface SecurityLogsResponse {
  logs: SecurityLog[];
  pagination: PaginationResponse;
}

/**
 * Risposta con sessioni utente
 */
export interface SessionsResponse {
  sessions: SecuritySession[];
}

/**
 * Dati per il download personale (GDPR)
 */
export interface DownloadDataResponse {
  download_url: string;
  expires_at: string;
  file_size: number;
  format: 'json' | 'csv' | 'xml';
}

// Tipi per le chiamate API
export type GetSecurityLogsResponse = ApiResponse<SecurityLogsResponse>;
export type GetSessionsResponse = ApiResponse<SessionsResponse>;
export type DownloadDataApiResponse = ApiResponse<DownloadDataResponse>;
export type DeleteAccountResponse = ApiResponse<null>; 