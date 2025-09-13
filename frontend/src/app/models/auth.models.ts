import { ApiResponse } from './api-base.models';

/**
 * Modelli per l'autenticazione PANDOM
 * Basati sulla struttura reale del backend
 */

/**
 * Ruoli utente disponibili
 */
export type UserRole = 'admin' | 'user';

/**
 * Stati di verifica
 */
export type VerificationStatus = 'pending' | 'verified' | 'expired';

/**
 * Dati per il login
 */
export interface LoginRequest {
  email: string;
  password: string;
  rememberMe?: boolean;
}

/**
 * Risposta al login
 */
export interface LoginResponseData {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  user: {
    uuid: string;
    email: string;
    role: UserRole;
    is_verified: boolean;
  };
}

/**
 * Dati per la registrazione
 */
export interface RegisterRequest {
  email: string;
  password: string;
}

/**
 * Dati per il refresh token
 */
export interface RefreshTokenRequest {
  refresh_token: string;
}

/**
 * Dati per il recupero password
 */
export interface ForgotPasswordRequest {
  email: string;
}

/**
 * Dati per il reset password
 */
export interface ResetPasswordRequest {
  otp: string;
  password: string;
}

/**
 * Dati per la verifica email
 */
export interface VerifyEmailRequest {
  token: string;
}

/**
 * Dati per il reinvio verifica email
 */
export interface ResendVerificationRequest {
  email: string;
}

/**
 * Dati utente completi (risposta /auth/me)
 */
export interface UserData {
  uuid: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  is_verified: boolean;
  is_configured: boolean;
  last_login_at?: string;
  profile_uuid?: string;
  created_at: string;
  updated_at: string;
  profile?: UserProfileData;
}

/**
 * Dati profilo utente
 */
export interface UserProfileData {
  uuid: string;
  tags: string[];
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

/**
 * Dati utente e profilo per la risposta /auth/me
 */
export interface GetMeData {
  user: UserData;
  profile: UserProfileData;
}

// Tipi per le chiamate API
export type LoginApiResponse = ApiResponse<LoginResponseData>;
export type RegisterApiResponse = ApiResponse<UserData>;
export type RefreshTokenApiResponse = ApiResponse<LoginResponseData>;
export type ForgotPasswordApiResponse = ApiResponse<{ message: string; expiresIn: number }>;
export type ResetPasswordApiResponse = ApiResponse<null>;
export type VerifyEmailApiResponse = ApiResponse<null>;
export type ResendVerificationApiResponse = ApiResponse<null>;
export type GetMeApiResponse = ApiResponse<GetMeData>;

