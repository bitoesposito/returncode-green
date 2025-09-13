

/**
 * Public user data interface
 * Used for public profile endpoints
 */
export interface User {
  name: string;
  surname: string;
  areaCode: string;
  phone: number;
  website: string;
  isWhatsappEnabled: boolean;
  isWebsiteEnabled: boolean;
  isVcardEnabled: boolean;
  slug: string;
  email: string;
  profilePhoto?: string;
}

/**
 * Private user data interface
 * Used for admin profile and operations endpoints
 */
export interface UserDetails extends User {
  uuid: string;
  role: UserRole;
  createdAt: string;
  is_configured: boolean;
  profile_photo?: string;
}

/**
 * User email interface
 * Used for body requests
 */
export interface UserEmail {
  email: string;
}

/**
 * Language interface
 * Used for language selection
 */
export interface Language {
  iso: string;
  code: string;
  lang: string;
}

/**
 * Modelli per la gestione utenti PANDOM
 * Basati sulla struttura reale del backend
 */

import { ApiResponse } from './api-base.models';
import { UserRole } from './auth.models';

/**
 * Dati per l'aggiornamento profilo
 */
export interface UpdateProfileRequest {
  tags?: string[];
  metadata?: Record<string, any>;
}

/**
 * Dati profilo utente
 */
export interface UserProfile {
  uuid: string;
  tags: string[];
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

/**
 * Dati utente completi con profilo
 */
export interface UserWithProfile {
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
  profile?: UserProfile;
}

// Tipi per le chiamate API
export type GetProfileResponse = ApiResponse<UserWithProfile>;
export type UpdateProfileResponse = ApiResponse<UserWithProfile>;