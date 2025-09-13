import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { environment } from '../../environments/environment';

/**
 * Certificate Service
 * 
 * Service for handling certificate-related API operations including
 * verification, download, and management. Provides centralized HTTP
 * client integration with proper error handling and response mapping.
 * 
 * Features:
 * - Certificate verification (public endpoint)
 * - Certificate download (authenticated)
 * - User certificate listing (authenticated)
 * - Certificate generation (admin only)
 * - Certificate revocation (admin only)
 * - Comprehensive error handling
 * - Response type safety
 * 
 * API Integration:
 * - Uses environment configuration for base URL
 * - Handles HTTP errors gracefully
 * - Maps API responses to typed interfaces
 * - Supports both authenticated and public endpoints
 */

// Response interfaces
export interface ApiResponse<T> {
  success: boolean;
  data: T;
  message: string;
  error?: string;
  statusCode?: number;
  timestamp?: string;
}

export interface VerificationResult {
  valid: boolean;
  certificate?: CertificateInfo;
  reason?: string;
  verified_at: Date;
  public_key_id?: string;
}

export interface CertificateInfo {
  id: string;
  user_email: string;
  course_name: string;
  description: string | null;
  issued_date: Date;
  revoked: boolean;
  public_key_id: string;
  metadata: Record<string, any>;
}

export interface CertificateResponse {
  id: string;
  user_uuid: string;
  user_email: string;
  course_name: string;
  description: string | null;
  issued_date: Date;
  file_path?: string;
  original_filename: string;
  content_type: string;
  file_size: number;
  public_key_id: string;
  revoked: boolean;
  revoked_at: Date | null;
  revoked_reason: string | null;
  metadata: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface GenerateCertificateRequest {
  user_uuid: string;
  course_name: string;
  description?: string;
  issued_date?: string;
  metadata?: Record<string, any>;
}

export interface RevokeCertificateRequest {
  reason: string;
  additional_details?: string;
}

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  
  private readonly apiUrl = `${environment.apiUrl}/certificates`;

  constructor(private http: HttpClient) {}

  // ============================================================================
  // PUBLIC CERTIFICATE OPERATIONS
  // ============================================================================

  /**
   * Verify certificate authenticity (public endpoint)
   * 
   * Verifies a certificate using its ID without requiring authentication.
   * This endpoint is publicly accessible for employers and institutions.
   * 
   * @param certificateId - UUID of certificate to verify
   * @returns Observable with verification result
   */
  verifyCertificate(certificateId: string): Observable<VerificationResult> {
    return this.http.get<ApiResponse<VerificationResult>>(
      `${this.apiUrl}/${certificateId}/verify`
    ).pipe(
      map(response => {
        if (response.success) {
          return response.data;
        } else {
          throw new Error(response.message || 'Verification failed');
        }
      }),
      catchError(this.handleError)
    );
  }

  // ============================================================================
  // AUTHENTICATED CERTIFICATE OPERATIONS
  // ============================================================================

  /**
   * Generate new certificate (admin only)
   * 
   * Creates a new certificate for a user with file upload.
   * Requires admin authentication and proper file data.
   * 
   * @param certificateData - Certificate generation data
   * @param file - Certificate file (PDF or JSON)
   * @returns Observable with generated certificate data
   */
  generateCertificate(
    certificateData: GenerateCertificateRequest, 
    file: File
  ): Observable<CertificateResponse> {
    const formData = new FormData();
    
    // Append certificate data
    formData.append('user_uuid', certificateData.user_uuid);
    formData.append('course_name', certificateData.course_name);
    
    if (certificateData.description) {
      formData.append('description', certificateData.description);
    }
    
    if (certificateData.issued_date) {
      formData.append('issued_date', certificateData.issued_date);
    }
    
    if (certificateData.metadata) {
      formData.append('metadata', JSON.stringify(certificateData.metadata));
    }
    
    // Append file
    formData.append('certificate_file', file, file.name);

    return this.http.post<ApiResponse<CertificateResponse>>(
      this.apiUrl,
      formData
    ).pipe(
      map(response => {
        if (response.success) {
          return response.data;
        } else {
          throw new Error(response.message || 'Certificate generation failed');
        }
      }),
      catchError(this.handleError)
    );
  }

  /**
   * Download certificate file
   * 
   * Downloads the certificate file for authenticated users.
   * Users can only download their own certificates unless they are admin.
   * 
   * @param certificateId - UUID of certificate to download
   * @returns Observable with file blob
   */
  downloadCertificate(certificateId: string): Observable<Blob> {
    return this.http.get(
      `${this.apiUrl}/${certificateId}/download`,
      { 
        responseType: 'blob',
        observe: 'response'
      }
    ).pipe(
      map(response => {
        if (response.body) {
          return response.body;
        } else {
          throw new Error('No file data received');
        }
      }),
      catchError(this.handleError)
    );
  }

  /**
   * Get user certificates
   * 
   * Retrieves list of certificates for a specific user.
   * Requires authentication and proper authorization.
   * 
   * @param userId - UUID of user whose certificates to retrieve
   * @returns Observable with array of certificates
   */
  getUserCertificates(userId: string): Observable<CertificateResponse[]> {
    return this.http.get<ApiResponse<CertificateResponse[]>>(
      `${this.apiUrl}/user/${userId}`
    ).pipe(
      map(response => {
        if (response.success) {
          return response.data;
        } else {
          throw new Error(response.message || 'Failed to retrieve certificates');
        }
      }),
      catchError(this.handleError)
    );
  }

  /**
   * Revoke certificate (admin only)
   * 
   * Marks a certificate as revoked, preventing future verifications.
   * Requires admin authentication and revocation reason.
   * 
   * @param certificateId - UUID of certificate to revoke
   * @param revocationData - Revocation details
   * @returns Observable with revocation confirmation
   */
  revokeCertificate(
    certificateId: string, 
    revocationData: RevokeCertificateRequest
  ): Observable<void> {
    return this.http.post<ApiResponse<void>>(
      `${this.apiUrl}/${certificateId}/revoke`,
      revocationData
    ).pipe(
      map(response => {
        if (response.success) {
          return response.data;
        } else {
          throw new Error(response.message || 'Certificate revocation failed');
        }
      }),
      catchError(this.handleError)
    );
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Download certificate file with proper filename
   * 
   * Helper method to download certificate and trigger browser download
   * with the original filename.
   * 
   * @param certificateId - UUID of certificate to download
   * @param filename - Optional custom filename
   */
  downloadCertificateFile(certificateId: string, filename?: string): void {
    this.downloadCertificate(certificateId).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename || `certificate-${certificateId}.pdf`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      },
      error: (error) => {
        console.error('Certificate download failed:', error);
        throw error;
      }
    });
  }

  /**
   * Validate certificate ID format
   * 
   * Checks if the provided string is a valid UUID format.
   * 
   * @param certificateId - Certificate ID to validate
   * @returns True if valid UUID format
   */
  isValidCertificateId(certificateId: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(certificateId);
  }

  /**
   * Format certificate verification result for display
   * 
   * Formats verification result data for consistent UI display.
   * 
   * @param result - Verification result from API
   * @returns Formatted result object
   */
  formatVerificationResult(result: VerificationResult): any {
    return {
      ...result,
      verified_at: new Date(result.verified_at),
      certificate: result.certificate ? {
        ...result.certificate,
        issued_date: new Date(result.certificate.issued_date)
      } : null
    };
  }

  /**
   * Get certificate status display text
   * 
   * Returns user-friendly status text based on certificate state.
   * 
   * @param certificate - Certificate data
   * @returns Status display text
   */
  getCertificateStatus(certificate: CertificateResponse): string {
    if (certificate.revoked) {
      return 'Revoked';
    }
    return 'Valid';
  }

  /**
   * Get certificate status severity for PrimeNG components
   * 
   * Returns appropriate severity level for PrimeNG status components.
   * 
   * @param certificate - Certificate data
   * @returns PrimeNG severity level
   */
  getCertificateStatusSeverity(certificate: CertificateResponse): string {
    if (certificate.revoked) {
      return 'danger';
    }
    return 'success';
  }

  // ============================================================================
  // ERROR HANDLING
  // ============================================================================

  /**
   * Handle HTTP errors
   * 
   * Centralized error handling for all HTTP operations.
   * Provides consistent error formatting and logging.
   * 
   * @param error - HTTP error response
   * @returns Observable error
   */
  private handleError = (error: HttpErrorResponse): Observable<never> => {
    let errorMessage = 'An unexpected error occurred';
    
    if (error.error instanceof ErrorEvent) {
      // Client-side error
      errorMessage = `Client Error: ${error.error.message}`;
    } else {
      // Server-side error
      if (error.error && error.error.message) {
        errorMessage = error.error.message;
      } else if (error.message) {
        errorMessage = error.message;
      } else {
        errorMessage = `Server Error: ${error.status} ${error.statusText}`;
      }
    }
    
    console.error('Certificate Service Error:', {
      error,
      message: errorMessage,
      status: error.status,
      url: error.url
    });
    
    return throwError(() => new Error(errorMessage));
  };
}