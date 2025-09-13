import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';
import { CookieAuthService } from '../services/cookie-auth.service';
import { Router } from '@angular/router';

/**
 * Cookie Authentication Interceptor
 * 
 * Handles authentication using secure httpOnly cookies instead of localStorage.
 * This interceptor:
 * - Automatically includes credentials in requests
 * - Handles token refresh when access token expires
 * - Manages authentication state
 * - Redirects to login on authentication failures
 * 
 * Security Features:
 * - Uses httpOnly cookies for token storage
 * - Prevents XSS attacks on tokens
 * - Maintains CSRF protection
 * - Automatic token refresh
 */
export const cookieAuthInterceptor: HttpInterceptorFn = (req, next) => {
  const cookieAuthService = inject(CookieAuthService);
  const router = inject(Router);

  // Add withCredentials to all requests to include cookies
  const cloned = req.clone({
    withCredentials: true
  });
  
  return next(cloned).pipe(
    catchError((error: HttpErrorResponse) => {
      // If we get a 401 (Unauthorized), try to refresh the token
      if (error.status === 401) {
        return cookieAuthService.refreshToken().pipe(
          switchMap((response) => {
            if (response.success && response.data) {
              // Token refreshed successfully, retry the original request
              const retryCloned = req.clone({
                withCredentials: true
              });
              return next(retryCloned);
            } else {
              // Refresh failed, redirect to login
              cookieAuthService.clearAllAuthData();
              router.navigate(['/login']);
              return throwError(() => error);
            }
          }),
          catchError((refreshError) => {
            // Refresh token failed, redirect to login
            cookieAuthService.forceLogout();
            router.navigate(['/login']);
            return throwError(() => refreshError);
          })
        );
      }
      
      return throwError(() => error);
    })
  );
}; 