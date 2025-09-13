/**
 * Modelli base per tutte le risposte API
 * Standardizzazione delle risposte del backend
 */

/**
 * Interfaccia generica per tutte le risposte API
 * Gestisce sia i casi di successo che di errore
 * @template T - Tipo dei dati restituiti in caso di successo
 */
export interface ApiResponse<T> {
  success: boolean;
  message: string;
  data: T | null;
  status?: number;  // Opzionale, presente solo in caso di errore
}

/**
 * Interfaccia per la paginazione standard
 * Utilizzata in tutte le risposte che supportano paginazione
 */
export interface PaginationResponse {
  page: number;
  limit: number;
  total: number;
  total_pages: number;
}

/**
 * Interfaccia per errori di validazione
 * Utilizzata quando il backend restituisce errori di validazione
 */
export interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

/**
 * Interfaccia per errori API dettagliati
 * Estende ApiResponse per gestire errori specifici
 */
export interface ApiErrorResponse {
  success: false;
  message: string;
  status: number;
  errors?: ValidationError[];
  timestamp: string;
  path: string;
}

/**
 * Interfaccia per risposte di successo senza dati
 * Utilizzata per operazioni che non restituiscono contenuto
 */
export interface SuccessResponse {
  success: true;
  message: string;
  data: null;
}

/**
 * Tipo union per tutte le possibili risposte API
 */
export type ApiResult<T> = ApiResponse<T> | ApiErrorResponse;

/**
 * Interfaccia per richieste con paginazione
 * Parametri standard per le richieste paginate
 */
export interface PaginationRequest {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

/**
 * Interfaccia per richieste con filtri di ricerca
 * Estende PaginationRequest con capacità di ricerca
 */
export interface SearchRequest extends PaginationRequest {
  search?: string;
  filters?: Record<string, any>;
} 